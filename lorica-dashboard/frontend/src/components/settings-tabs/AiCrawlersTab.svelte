<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type BuiltinCrawler,
    type CustomCrawler,
    type AiCrawlerTestResponse,
  } from '../../lib/api';
  import {
    crawlerToEdit,
    editToBody,
    emptyCrawlerEdit,
    verificationKindLabel,
    verificationKindTooltip,
    verificationSummary,
    type CrawlerEditState,
  } from '../../lib/ai-crawlers';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';
  import { canWrite } from '../../lib/auth';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  let builtins = $state<BuiltinCrawler[]>([]);
  let customs = $state<CustomCrawler[]>([]);
  let builtInCount = $state(0);
  let maxCount = $state(0);
  let loading = $state(false);
  let loadError = $state('');

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    const [bRes, cRes] = await Promise.all([
      api.getAiCrawlersBuiltin(),
      api.getAiCrawlersCustom(),
    ]);
    if (bRes.error) {
      loadError = bRes.error.message;
    } else if (bRes.data) {
      builtins = bRes.data.entries;
    }
    if (cRes.error) {
      loadError = cRes.error.message;
    } else if (cRes.data) {
      customs = cRes.data.entries;
      builtInCount = cRes.data.built_in_count;
      maxCount = cRes.data.max_count;
    }
    loading = false;
  }

  onMount(load);

  let capReached = $derived(maxCount > 0 && customs.length >= maxCount);

  // Create / edit form state.
  let showForm = $state(false);
  let editingId = $state<number | null>(null);
  let edit = $state<CrawlerEditState>(emptyCrawlerEdit());
  let formError = $state('');
  let saving = $state(false);
  let deletingId = $state<number | null>(null);

  // "Test pattern" widget inside the form.
  let testUa = $state('');
  let testResult = $state<AiCrawlerTestResponse | null>(null);
  let testError = $state<string | null>(null);
  let testLoading = $state(false);

  function resetTest(): void {
    testUa = '';
    testResult = null;
    testError = null;
  }

  function openCreate(): void {
    editingId = null;
    edit = emptyCrawlerEdit();
    formError = '';
    resetTest();
    showForm = true;
  }

  function openEdit(c: CustomCrawler): void {
    editingId = c.id;
    edit = crawlerToEdit(c);
    formError = '';
    resetTest();
    showForm = true;
  }

  async function save(): Promise<void> {
    if (!edit.name.trim()) {
      formError = 'Name is required.';
      return;
    }
    if (!edit.user_agent_pattern.trim()) {
      formError = 'User-Agent pattern is required.';
      return;
    }
    saving = true;
    formError = '';
    const body = editToBody(edit);
    const res =
      editingId !== null
        ? await api.updateAiCrawlerCustom(editingId, body)
        : await api.createAiCrawlerCustom(body);
    if (res.error) {
      formError = res.error.message;
      saving = false;
      return;
    }
    if (editingId !== null) {
      customs = customs.map((x) => (x.id === editingId ? (res.data ?? x) : x));
      showToast('Crawler updated', 'success');
    } else if (res.data) {
      customs = [...customs, res.data];
      showToast('Crawler created', 'success');
    }
    showForm = false;
    saving = false;
  }

  async function toggleEnabled(c: CustomCrawler): Promise<void> {
    const body = editToBody(crawlerToEdit(c));
    body.enabled = !c.enabled;
    const res = await api.updateAiCrawlerCustom(c.id, body);
    if (res.error) {
      showToast(res.error.message, 'error');
    } else {
      customs = customs.map((x) => (x.id === c.id ? (res.data ?? x) : x));
    }
  }

  async function confirmDelete(): Promise<void> {
    if (deletingId === null) return;
    const id = deletingId;
    const res = await api.deleteAiCrawlerCustom(id);
    if (res.error) {
      showToast(res.error.message, 'error');
    } else {
      customs = customs.filter((x) => x.id !== id);
    }
    deletingId = null;
  }

  async function runTest(): Promise<void> {
    const ua = testUa.trim();
    if (ua === '') {
      testError = 'Enter a User-Agent string to test.';
      testResult = null;
      return;
    }
    testLoading = true;
    testError = null;
    const res = await api.testAiCrawler(ua);
    if (res.error) {
      testError = res.error.message;
      testResult = null;
    } else {
      testResult = res.data ?? null;
    }
    testLoading = false;
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>AI Crawlers</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">
        AI / LLM crawler registry. Built-in entries ship with Lorica; custom entries
        let you classify additional bots. The per-route action lives in
        Routes &gt; Advanced Configuration &gt; Protection &gt; AI crawler policy.
      </p>

      {#if loadError}
        <div class="settings-form-error">{loadError}</div>
      {/if}
      {#if loading}
        <p class="settings-hint">Loading...</p>
      {/if}

      <h3>Built-in crawlers</h3>
      <div class="settings-table-wrap">
        <table class="settings-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>UA pattern</th>
              <th>Verification</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {#each builtins as b (b.name)}
              <tr>
                <td><code>{b.name}</code></td>
                <td class="ua-cell"><code>{b.user_agent_pattern}</code></td>
                <td>
                  <span class="badge badge-verify" title={verificationKindTooltip(b.verification_kind)}>
                    {verificationKindLabel(b.verification_kind)}
                  </span>
                </td>
                <td class="text-muted">{b.source}</td>
              </tr>
            {/each}
            {#if builtins.length === 0 && !loading}
              <tr><td colspan="4" class="text-muted">No built-in crawlers.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>

      <h3>Custom crawlers</h3>
      <div class="settings-table-wrap">
        <table class="settings-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>UA pattern</th>
              <th>Verification</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each customs as c (c.id)}
              <tr>
                <td><code>{c.name}</code></td>
                <td class="ua-cell"><code>{c.user_agent_pattern}</code></td>
                <td>
                  <span class="badge badge-verify" title={verificationKindTooltip(c.verification.kind)}>
                    {verificationSummary(c.verification)}
                  </span>
                </td>
                <td>
                  <label class="toggle-cell">
                    <input type="checkbox" checked={c.enabled} disabled={!$canWrite} onchange={() => toggleEnabled(c)} />
                    <span>{c.enabled ? 'On' : 'Off'}</span>
                  </label>
                </td>
                <td class="settings-actions-cell">
                  {#if $canWrite}
                    <button class="settings-btn-action settings-btn-edit" onclick={() => openEdit(c)}>Edit</button>
                    <button class="settings-btn-action settings-btn-delete" onclick={() => (deletingId = c.id)}>Delete</button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if customs.length === 0 && !loading}
              <tr><td colspan="5" class="text-muted">No custom crawlers yet.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>

      <div class="settings-dialog-actions count-row">
        <span class="settings-hint count-hint">
          {customs.length} custom{maxCount > 0 ? ` / ${maxCount} max` : ''}
          {builtInCount > 0 ? ` (+${builtInCount} built-in)` : ''}
        </span>
        {#if $canWrite}
          <button class="btn btn-primary" onclick={openCreate} disabled={capReached}>Add Crawler</button>
        {/if}
      </div>
      {#if capReached}
        <span class="field-error" role="alert">Custom crawler cap reached. Delete one before adding another.</span>
      {/if}
    </div>
  {/if}
</section>

<!-- Create / edit form modal -->
{#if showForm}
  <div class="settings-overlay" onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="settings-dialog" role="document">
      <h3>{editingId !== null ? 'Edit' : 'Add'} Custom Crawler</h3>

      <div class="settings-form-row">
        <label for="crawler-name">Name <span class="settings-required">*</span></label>
        <input id="crawler-name" type="text" bind:value={edit.name} placeholder="e.g. MyCorpBot" autocomplete="off" spellcheck="false" />
      </div>

      <div class="settings-form-row">
        <label for="crawler-ua">User-Agent pattern <span class="settings-required">*</span></label>
        <input id="crawler-ua" type="text" bind:value={edit.user_agent_pattern} placeholder="e.g. MyCorpBot/1\.0" autocomplete="off" spellcheck="false" />
        <span class="settings-hint">Rust <code>regex</code> syntax. Must not collide with a baseline (built-in) UA.</span>
        {#if formError}<span class="field-error" role="alert">{formError}</span>{/if}
      </div>

      <div class="settings-form-row">
        <label for="crawler-kind">Verification</label>
        <select id="crawler-kind" bind:value={edit.kind}>
          <option value="ua_only">UA only (no network check)</option>
          <option value="rdns">rDNS (forward-confirmed reverse DNS)</option>
          <option value="ip_ranges">IP ranges (published CIDRs)</option>
        </select>
        <span class="settings-hint">{verificationKindTooltip(edit.kind)}</span>
      </div>

      {#if edit.kind === 'rdns'}
        <div class="settings-form-row">
          <label for="crawler-suffixes">rDNS suffixes</label>
          <textarea id="crawler-suffixes" rows="3" bind:value={edit.suffixes} placeholder="googlebot.com&#10;search.msn.com" autocomplete="off" spellcheck="false"></textarea>
          <span class="settings-hint">One suffix per line (or comma-separated). The client PTR must end with one of these and resolve back to the same IP.</span>
        </div>
      {:else if edit.kind === 'ip_ranges'}
        <div class="settings-form-row">
          <label for="crawler-cidrs">IP ranges (CIDR)</label>
          <textarea id="crawler-cidrs" rows="3" bind:value={edit.cidrs} placeholder="203.0.113.0/24&#10;2001:db8::/32" autocomplete="off" spellcheck="false"></textarea>
          <span class="settings-hint">One CIDR per line (or comma-separated). Max 64 entries.</span>
        </div>
      {/if}

      <div class="settings-form-row">
        <label class="toggle-cell">
          <input type="checkbox" bind:checked={edit.enabled} />
          <span>Enabled</span>
        </label>
      </div>

      <div class="settings-form-row test-block">
        <label for="crawler-test-ua">Test pattern against a sample UA</label>
        <div class="test-row">
          <input id="crawler-test-ua" type="text" bind:value={testUa} placeholder="Paste a User-Agent string" autocomplete="off" spellcheck="false" />
          <button type="button" class="btn btn-cancel" onclick={runTest} disabled={testLoading}>{testLoading ? 'Testing...' : 'Test'}</button>
        </div>
        {#if testError}<span class="field-error" role="alert">{testError}</span>{/if}
        {#if testResult}
          {#if testResult.matched_crawler}
            <span class="settings-hint test-result">
              Matched: {testResult.matched_crawler} ; Verification: {testResult.verification_kind ? verificationKindLabel(testResult.verification_kind) : 'none'}
            </span>
            <span class="settings-hint test-result-note">
              Policy depends on the route; test from a route's Protection tab to see the applied policy.
            </span>
          {:else}
            <span class="settings-hint test-result">No AI bot match{testResult.note ? ` - ${testResult.note}` : ''}</span>
          {/if}
        {/if}
      </div>

      <div class="settings-dialog-actions">
        <button class="btn btn-cancel" onclick={() => (showForm = false)}>Cancel</button>
        <button class="btn btn-primary" onclick={save} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete confirm -->
{#if deletingId !== null}
  <ConfirmDialog
    title="Delete Custom Crawler"
    message="Delete this custom crawler? Routes using AI crawler policy will stop matching it."
    onconfirm={confirmDelete}
    oncancel={() => (deletingId = null)}
  />
{/if}

<style>
  h3 {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }

  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 500;
  }
  .badge-verify {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
    cursor: help;
  }

  .ua-cell code {
    font-family: var(--mono);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
  }

  .text-muted {
    color: var(--color-text-muted);
    font-size: var(--text-xs);
  }

  .toggle-cell {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    cursor: pointer;
  }
  .toggle-cell input[type="checkbox"] { accent-color: var(--color-primary); }

  .count-row {
    align-items: center;
    justify-content: space-between;
  }
  .count-hint { margin: 0; }

  .test-block { border-top: 1px dashed var(--color-border); padding-top: 0.75rem; }
  .test-row { display: flex; gap: 0.5rem; }
  .test-row input { flex: 1; }
  .test-result { margin-top: 0.375rem; color: var(--color-text); }
  .test-result-note { margin-top: 0.25rem; color: var(--color-text-muted); font-size: var(--text-xs); }

  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
</style>
