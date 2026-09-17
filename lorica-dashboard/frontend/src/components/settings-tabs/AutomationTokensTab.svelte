<script lang="ts" module>
  import type { AutomationScope } from '../../lib/api';

  /**
   * The closed scope enum, in the order the create form offers it:
   * the reads first, because a token that only reads is the one an
   * operator should reach for by default.
   *
   * These strings are the wire spelling, owned by Rust: the
   * `#[serde(rename = "...")]` attributes on `AutomationScope` in
   * `lorica-config/src/models/automation_token.rs` and `scope_str` in
   * `lorica-api/src/automation/scope.rs`. Nothing generates this
   * client, so `automation-scopes.fixture.ts` beside this file pins
   * the set and the test fails if a rename lands on one side only.
   * Exported for that test and for no other reason.
   */
  export const ALL_SCOPES: { value: AutomationScope; label: string }[] = [
    { value: 'environments:read', label: 'environments:read' },
    { value: 'routes:read', label: 'routes:read' },
    { value: 'certificates:read', label: 'certificates:read' },
    { value: 'environments:write', label: 'environments:write' },
  ];
</script>

<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type AutomationTokenResponse,
  } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';
  import { isSuperAdmin } from '../../lib/auth';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  let tokens = $state<AutomationTokenResponse[]>([]);
  let loading = $state(false);
  let loadError = $state('');

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    const res = await api.listAutomationTokens();
    if (res.error) {
      loadError = res.error.message;
    } else if (res.data) {
      tokens = res.data.tokens;
    }
    loading = false;
  }

  onMount(load);

  // ---- Create ----

  let showForm = $state(false);
  let formName = $state('');
  let formScopes = $state<AutomationScope[]>(['environments:read']);
  let formHostnames = $state('');
  let formBackendCidrs = $state('');
  let formLifetimeDays = $state('');
  let formMaxTtlSeconds = $state('');
  let formError = $state('');
  let saving = $state(false);

  /**
   * The full token, held only between the mint answer and the moment
   * the operator dismisses it. The node keeps an HMAC of the secret
   * and nothing else, so nothing on this page can fetch it back: once
   * this goes to null it is gone for good.
   */
  let mintedToken = $state<string | null>(null);
  let copied = $state(false);

  function lines(value: string): string[] {
    return value
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }

  function openCreate(): void {
    formName = '';
    formScopes = ['environments:read'];
    formHostnames = '';
    formBackendCidrs = '';
    formLifetimeDays = '';
    formMaxTtlSeconds = '';
    formError = '';
    showForm = true;
  }

  function toggleScope(scope: AutomationScope): void {
    formScopes = formScopes.includes(scope)
      ? formScopes.filter((s) => s !== scope)
      : [...formScopes, scope];
  }

  async function create(): Promise<void> {
    saving = true;
    formError = '';
    const lifetime = formLifetimeDays.trim();
    const maxTtl = formMaxTtlSeconds.trim();
    // Omitted fields are omitted, never sent as null: the API takes an
    // absent field as "use the model's default", and the model owns
    // every cap. The form restates none of them, so a refusal here is
    // the server's message verbatim.
    const res = await api.createAutomationToken({
      name: formName.trim(),
      scopes: formScopes,
      allowed_hostnames: lines(formHostnames),
      ...(lines(formBackendCidrs).length > 0
        ? { allowed_backend_cidrs: lines(formBackendCidrs) }
        : {}),
      ...(lifetime !== '' ? { lifetime_days: Number(lifetime) } : {}),
      ...(maxTtl !== '' ? { max_ttl_seconds: Number(maxTtl) } : {}),
    });
    saving = false;
    if (res.error) {
      formError = res.error.message;
      return;
    }
    if (res.data) {
      const { token, ...row } = res.data;
      tokens = [row, ...tokens];
      mintedToken = token;
      copied = false;
      showForm = false;
    }
  }

  async function copyToken(): Promise<void> {
    if (mintedToken === null) return;
    try {
      await navigator.clipboard.writeText(mintedToken);
      copied = true;
    } catch {
      showToast('Could not copy; select the token and copy it manually.', 'error');
    }
  }

  function dismissToken(): void {
    mintedToken = null;
    copied = false;
  }

  // ---- Revoke ----

  let revokingId = $state<string | null>(null);

  async function confirmRevoke(): Promise<void> {
    if (revokingId === null) return;
    const publicId = revokingId;
    revokingId = null;
    const res = await api.revokeAutomationToken(publicId);
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    if (res.data) {
      const updated = res.data;
      tokens = tokens.map((t) => (t.public_id === publicId ? updated : t));
      showToast('Token revoked. It is refused on its next request.', 'success');
    }
  }

  function when(value: string | null): string {
    return value === null ? 'never' : new Date(value).toLocaleString();
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Automation Tokens</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">
        Scoped bearer credentials for the automation listener. Each token is
        limited to the scopes, hostnames and backend ranges you give it here,
        and it is refused the moment you revoke it. The full token is shown
        once, when it is minted, and cannot be recovered afterwards.
      </p>

      {#if loadError}
        <div class="settings-form-error">{loadError}</div>
      {/if}
      {#if loading}
        <p class="settings-hint">Loading...</p>
      {/if}

      <div class="settings-table-wrap">
        <table class="settings-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Public id</th>
              <th>Scopes</th>
              <th>Hostnames</th>
              <th>Expires</th>
              <th>Last used</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each tokens as token (token.public_id)}
              <tr class:revoked={token.revoked_at !== null}>
                <td>
                  {token.name}
                  {#if token.revoked_at !== null}
                    <span class="badge badge-revoked">Revoked</span>
                  {/if}
                </td>
                <td><code>{token.public_id}</code></td>
                <td>
                  {#each token.scopes as scope (scope)}
                    <span class="badge badge-scope">{scope}</span>
                  {/each}
                </td>
                <td class="wrap-cell">
                  {#each token.allowed_hostnames as hostname (hostname)}
                    <code>{hostname}</code>
                  {/each}
                </td>
                <td class="text-muted">{when(token.expires_at)}</td>
                <td class="text-muted">{when(token.last_used_at)}</td>
                <td class="settings-actions-cell">
                  {#if $isSuperAdmin && token.revoked_at === null}
                    <button
                      class="settings-btn-action settings-btn-delete"
                      onclick={() => (revokingId = token.public_id)}
                    >
                      Revoke
                    </button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if tokens.length === 0 && !loading}
              <tr><td colspan="7" class="text-muted">No automation tokens yet.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>

      {#if $isSuperAdmin}
        <div class="settings-dialog-actions">
          <button class="btn btn-primary" onclick={openCreate}>Create Token</button>
        </div>
      {/if}
    </div>
  {/if}
</section>

<!-- Create form -->
{#if showForm}
  <div
    class="settings-overlay"
    onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }}
    onkeydown={(e) => { if (e.key === 'Escape') showForm = false; }}
    role="dialog"
    aria-modal="true"
    tabindex="-1"
  >
    <div class="settings-dialog" role="document">
      <h3>Create Automation Token</h3>

      <div class="settings-form-row">
        <label for="automation-token-name">Name <span class="settings-required">*</span></label>
        <input
          id="automation-token-name"
          type="text"
          bind:value={formName}
          placeholder="e.g. ci pipeline"
          autocomplete="off"
          spellcheck="false"
        />
      </div>

      <fieldset class="settings-form-row">
        <legend>Scopes <span class="settings-required">*</span></legend>
        {#each ALL_SCOPES as scope (scope.value)}
          <label class="toggle-cell">
            <input
              type="checkbox"
              checked={formScopes.includes(scope.value)}
              onchange={() => toggleScope(scope.value)}
            />
            <span>{scope.label}</span>
          </label>
        {/each}
      </fieldset>

      <div class="settings-form-row">
        <label for="automation-token-hostnames">
          Allowed hostnames <span class="settings-required">*</span>
        </label>
        <textarea
          id="automation-token-hostnames"
          rows="3"
          bind:value={formHostnames}
          placeholder="api.example.com&#10;*.preview.example.com"
          autocomplete="off"
          spellcheck="false"
        ></textarea>
        <span class="settings-hint">
          One per line. An exact name, or a single leading <code>*.</code> wildcard
          covering one label, the way a certificate wildcard reads.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="automation-token-cidrs">Allowed backend CIDRs</label>
        <textarea
          id="automation-token-cidrs"
          rows="2"
          bind:value={formBackendCidrs}
          placeholder="10.0.0.0/8"
          autocomplete="off"
          spellcheck="false"
        ></textarea>
        <span class="settings-hint">
          One per line. Leave empty to apply the node's default backend policy.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="automation-token-lifetime">Lifetime (days)</label>
        <input
          id="automation-token-lifetime"
          type="number"
          bind:value={formLifetimeDays}
          placeholder="365"
          autocomplete="off"
        />
        <span class="settings-hint">Leave empty for the default.</span>
      </div>

      <div class="settings-form-row">
        <label for="automation-token-max-ttl">Environment TTL ceiling (seconds)</label>
        <input
          id="automation-token-max-ttl"
          type="number"
          bind:value={formMaxTtlSeconds}
          placeholder="604800"
          autocomplete="off"
        />
        <span class="settings-hint">
          The longest lifetime an environment this token creates may request.
          Leave empty for the default.
        </span>
        {#if formError}<span class="field-error" role="alert">{formError}</span>{/if}
      </div>

      <div class="settings-dialog-actions">
        <button class="btn btn-cancel" onclick={() => (showForm = false)}>Cancel</button>
        <button class="btn btn-primary" onclick={create} disabled={saving}>
          {saving ? 'Creating...' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!--
  The one-time display. Deliberately NOT dismissible by clicking the
  backdrop or pressing Escape: the secret cannot be fetched again, so
  a stray click that closes this dialog costs the operator the
  credential they just created. Only the explicit button closes it.
-->
{#if mintedToken !== null}
  <div class="settings-overlay" role="dialog" aria-modal="true" aria-labelledby="minted-token-title">
    <div class="settings-dialog" role="document">
      <h3 id="minted-token-title">Copy this token now</h3>
      <p class="warning" role="alert">
        This is the only time this token will be shown. Lorica stores a hash of
        it and cannot display it again. If you lose it, revoke this token and
        create another.
      </p>
      <pre class="token" data-testid="minted-token">{mintedToken}</pre>
      <div class="settings-dialog-actions">
        <button class="btn btn-cancel" onclick={copyToken}>
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button class="btn btn-primary" onclick={dismissToken}>I have saved it</button>
      </div>
    </div>
  </div>
{/if}

<!-- Revoke confirm -->
{#if revokingId !== null}
  <ConfirmDialog
    title="Revoke Automation Token"
    message="Revoke this token? Any automation still presenting it is refused on its next request. The row is kept, with the revocation timestamp, so the audit trail survives."
    confirmLabel="Revoke"
    onconfirm={confirmRevoke}
    oncancel={() => (revokingId = null)}
  />
{/if}

<style>
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 500;
    margin-right: 0.25rem;
  }
  .badge-scope {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
  }
  .badge-revoked {
    background: var(--color-red);
    color: white;
  }

  tr.revoked {
    opacity: 0.6;
  }

  .wrap-cell code {
    display: block;
    font-family: var(--mono);
    font-size: 0.8125rem;
  }

  .text-muted {
    color: var(--color-text-muted);
    font-size: var(--text-xs);
  }

  .toggle-cell {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    cursor: pointer;
  }
  .toggle-cell input[type='checkbox'] {
    accent-color: var(--color-primary);
  }

  fieldset {
    border: none;
    padding: 0;
    margin: 0;
  }
  legend {
    padding: 0;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
  }

  .warning {
    color: var(--color-red);
    font-size: 0.875rem;
    line-height: 1.5;
  }

  .token {
    font-family: var(--mono);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    padding: 0.75rem;
    border-radius: 0.375rem;
    word-break: break-all;
    white-space: pre-wrap;
    user-select: all;
  }

  .field-error {
    display: block;
    color: var(--color-red);
    font-size: var(--text-xs);
    margin-top: 0.25rem;
  }
</style>
