<script lang="ts">
  import { api, type UserPreferenceResponse } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';

  interface Props {
    preferences: UserPreferenceResponse[];
    expanded: boolean;
    toggleSection: () => void;
    onReload: () => Promise<void>;
  }

  let {
    preferences,
    expanded,
    toggleSection,
    onReload,
  }: Props = $props();

  const HELPER_KEY = 'lorica_helper_dismissed';
  const SS_PREF_KEY = 'lorica_self_signed_pref';

  let helperGuideVisible = $state(localStorage.getItem(HELPER_KEY) !== 'true');
  let selfSignedPrefValue = $state<string | null>(localStorage.getItem(SS_PREF_KEY));
  let deletingPref: UserPreferenceResponse | null = $state(null);

  function toggleHelperGuide() {
    helperGuideVisible = !helperGuideVisible;
    if (helperGuideVisible) {
      localStorage.removeItem(HELPER_KEY);
    } else {
      localStorage.setItem(HELPER_KEY, 'true');
    }
  }

  function setSelfSignedPref(value: 'never' | 'always' | 'once') {
    localStorage.setItem(SS_PREF_KEY, value);
    selfSignedPrefValue = value;
  }

  async function changePrefValue(pref: UserPreferenceResponse, newVal: string) {
    await api.updatePreference(pref.id, newVal);
    await onReload();
  }

  async function confirmDeletePref() {
    if (!deletingPref) return;
    await api.deletePreference(deletingPref.id);
    deletingPref = null;
    await onReload();
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Preference Memory</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">Stored decisions for prompts and UI preferences.</p>

      <div class="pref-row">
        <div class="pref-info">
          <code>getting_started_guide</code>
          <span class="pref-hint">Show the getting started guide on the Overview page</span>
        </div>
        <label class="toggle-label">
          <span>{helperGuideVisible ? 'Visible' : 'Hidden'}</span>
          <button class="toggle" class:on={helperGuideVisible} onclick={toggleHelperGuide} aria-label="Toggle helper guide visibility">
            <span class="toggle-knob"></span>
          </button>
        </label>
      </div>

      <div class="pref-row">
        <div class="pref-info">
          <code>self_signed_cert</code>
          <span class="pref-hint">Self-signed certificate generation prompt preference</span>
        </div>
        <div class="toggle-triple">
          <button class:active={selfSignedPrefValue === 'never'} onclick={() => setSelfSignedPref('never')}>Never</button>
          <button class:active={selfSignedPrefValue === 'once' || !selfSignedPrefValue} onclick={() => setSelfSignedPref('once')}>Ask</button>
          <button class:active={selfSignedPrefValue === 'always'} onclick={() => setSelfSignedPref('always')}>Always</button>
        </div>
      </div>

      {#if preferences.length === 0}
        <p class="settings-empty-text">No other stored preferences.</p>
      {:else}
        <div class="settings-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each preferences as pref}
                <tr>
                  <td><code>{pref.preference_key}</code></td>
                  <td>
                    <select
                      value={pref.value}
                      onchange={(e) => changePrefValue(pref, (e.target as HTMLSelectElement).value)}
                    >
                      <option value="never">never</option>
                      <option value="always">always</option>
                      <option value="once">once</option>
                    </select>
                  </td>
                  <td class="settings-actions-cell">
                    <button class="btn-link danger" onclick={() => deletingPref = pref}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
</section>

{#if deletingPref}
  <ConfirmDialog
    title="Delete Preference"
    message="Are you sure you want to delete the preference '{deletingPref.preference_key}'?"
    onconfirm={confirmDeletePref}
    oncancel={() => deletingPref = null}
  />
{/if}

<style>
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  th {
    text-align: left;
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-weight: 500;
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  td {
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }

  td code {
    font-family: var(--mono);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
  }

  td select {
    padding: 0.25rem 0.5rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .btn-link {
    background: none;
    border: none;
    color: var(--color-primary);
    font-size: 0.8125rem;
    padding: 0;
    cursor: pointer;
  }

  .btn-link:hover {
    text-decoration: underline;
  }

  .btn-link.danger {
    color: var(--color-red);
  }

  .pref-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-4);
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .pref-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .pref-hint {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }

  .toggle {
    position: relative;
    width: 36px;
    min-width: 36px;
    max-width: 36px;
    height: 20px;
    min-height: 20px;
    max-height: 20px;
    border-radius: var(--radius-full);
    border: none;
    background: var(--color-bg-input);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    padding: 0;
    flex-shrink: 0;
  }

  .toggle.on {
    background: var(--color-green);
  }

  .toggle-knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: white;
    transition: transform var(--transition-fast);
  }

  .toggle.on .toggle-knob {
    transform: translateX(16px);
  }

  .toggle-triple {
    display: inline-flex;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .toggle-triple button {
    padding: 0.25rem 0.75rem;
    font-size: var(--text-xs);
    border: none;
    background: var(--color-bg-input);
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .toggle-triple button:not(:last-child) {
    border-right: 1px solid var(--color-border);
  }

  .toggle-triple button.active {
    background: var(--color-primary);
    color: white;
    font-weight: 600;
  }

  .toggle-triple button:hover:not(.active) {
    background: var(--color-bg-hover);
  }
</style>
