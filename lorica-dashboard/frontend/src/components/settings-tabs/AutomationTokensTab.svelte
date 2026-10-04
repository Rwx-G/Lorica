<script lang="ts" module>
  import type { AutomationScope } from '../../lib/api';
  import {
    AUTOMATION_SCOPE_WIRE_STRINGS,
    GRANT_BOUNDED_SCOPES,
    MCP_TIERS,
    type McpTier,
  } from './automation-scopes.generated';

  /**
   * What the create form offers, derived from the wire vocabulary
   * rather than restated: a scope added to the Rust enum reaches this
   * form through `automation-scopes.generated.ts` with nothing to
   * remember here.
   *
   * The label is the wire string itself, because a second vocabulary
   * in the UI is a second thing an operator has to map back to what a
   * 403 says. The order puts the writes last, so the reads an operator
   * should reach for by default come first; `sort` is stable, so the
   * reads keep the generated file's order.
   *
   * Exported for the test beside this file and for no other reason.
   */
  export const ALL_SCOPES: { value: AutomationScope; label: string }[] = [
    ...AUTOMATION_SCOPE_WIRE_STRINGS,
  ]
    .sort((a, b) => Number(a.endsWith(':write')) - Number(b.endsWith(':write')))
    .map((value) => ({ value, label: value }));

  /**
   * Whether a token carrying `scopes` has hostname and backend grants
   * at all. The node requires both when one of these scopes is carried
   * and refuses both when none is (typed absence), so a token without
   * one has no blast radius to show and the form has nothing to ask.
   * The set is `GRANT_BOUNDED_SCOPES`, which a Rust test pins against
   * the enum.
   *
   * Exported for the test beside this file and for no other reason.
   */
  export function carriesGrants(scopes: readonly AutomationScope[]): boolean {
    return scopes.some((scope) => GRANT_BOUNDED_SCOPES.includes(scope));
  }

  /** What `readMcpTier` answers: the shape of an `McpTierVector`. */
  export interface McpTierReading {
    tier: McpTier | null;
    anchoring: AutomationScope[];
    offending: AutomationScope[];
  }

  /**
   * The MCP tier a token carrying `scopes` would be, read the way
   * `lorica-mcp` reads it before it starts: the highest-reaching tier
   * whose required set the scopes touch, the scopes that name it, and
   * the scopes that tier does not allow. Any offending scope means the
   * token spans two tiers and `lorica-mcp` refuses it.
   *
   * A second implementation of `resolve` in `lorica-automation-policy`,
   * which is why it reads nothing but `MCP_TIERS` and why the test
   * beside this file replays every `MCP_TIER_VECTORS` entry through it:
   * the vectors are rendered from the Rust side, so the two cannot
   * disagree without one suite going red.
   *
   * Exported for the test beside this file and for no other reason.
   */
  export function readMcpTier(scopes: readonly AutomationScope[]): McpTierReading {
    const reach = (scope: AutomationScope): number =>
      MCP_TIERS.findIndex((definition) => definition.requires.includes(scope));
    const highest = Math.max(-1, ...scopes.map(reach));
    if (highest < 0) {
      return { tier: null, anchoring: [], offending: [...scopes] };
    }
    const definition = MCP_TIERS[highest];
    return {
      tier: definition.tier,
      anchoring: scopes.filter((scope) => definition.requires.includes(scope)),
      offending: scopes.filter(
        (scope) =>
          !definition.requires.includes(scope) && !definition.tolerates.includes(scope),
      ),
    };
  }
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
  let formTier = $derived(readMcpTier(formScopes));

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
    // the server's message verbatim. The grants are sent only when a
    // scope they bound is selected: text typed before the operator
    // unticked the last such scope is not a grant the token can carry.
    const grants = carriesGrants(formScopes)
      ? {
          allowed_hostnames: lines(formHostnames),
          allowed_backend_cidrs: lines(formBackendCidrs),
        }
      : {};
    const res = await api.createAutomationToken({
      name: formName.trim(),
      scopes: formScopes,
      ...grants,
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
                  {#if carriesGrants(token.scopes)}
                    {#each token.allowed_hostnames as hostname (hostname)}
                      <code>{hostname}</code>
                    {/each}
                  {:else}
                    <!--
                      A row minted before typed absence may still store
                      grants; no path this token reaches reads them, so
                      they are not its blast radius and are not shown.
                    -->
                    <span class="text-muted">not applicable</span>
                  {/if}
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

      <!--
        A hint and never a block: the automation plane accepts a token
        spanning two tiers, and only lorica-mcp refuses one.
      -->
      {#if formTier.tier !== null && formTier.offending.length === 0}
        <p class="settings-hint" data-testid="mcp-tier-hint">
          MCP tier: <strong>{formTier.tier}</strong>. lorica-mcp serves a token carrying
          these scopes as its {formTier.tier} tier.
        </p>
      {:else if formTier.tier !== null}
        <p class="tier-warning" role="status" data-testid="mcp-tier-warning">
          These scopes span more than one MCP tier: {formTier.anchoring.join(', ')}
          {formTier.anchoring.length === 1 ? 'makes' : 'make'} it the {formTier.tier} tier,
          which does not allow {formTier.offending.join(', ')}. The automation plane
          accepts this token, but it cannot start lorica-mcp; mint one token per tier
          to use it there.
        </p>
      {/if}

      {#if carriesGrants(formScopes)}
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
          <label for="automation-token-cidrs">
            Allowed backend CIDRs <span class="settings-required">*</span>
          </label>
          <textarea
            id="automation-token-cidrs"
            rows="2"
            bind:value={formBackendCidrs}
            placeholder="10.0.0.0/8"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
          <span class="settings-hint">
            One per line. An empty list admits no address: there is no node-wide
            default to fall back on.
          </span>
        </div>
      {:else}
        <p class="settings-hint">
          Hostname and backend grants: not applicable. None of the selected scopes
          reaches a path that reads them, so the token carries none.
        </p>
      {/if}

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

  .tier-warning {
    color: var(--color-orange);
    font-size: 0.8125rem;
    line-height: 1.5;
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
