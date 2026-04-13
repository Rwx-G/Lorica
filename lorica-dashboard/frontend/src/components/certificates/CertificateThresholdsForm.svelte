<script lang="ts">
  import { api } from '../../lib/api';

  interface Props {
    warningDays: number;
    criticalDays: number;
    onClose: () => void;
    onSaved: (warning: number, critical: number) => void;
  }

  let { warningDays, criticalDays, onClose, onSaved }: Props = $props();

  let thresholdWarning = $state(warningDays);
  let thresholdCritical = $state(criticalDays);

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
  }

  async function save() {
    if (thresholdCritical >= thresholdWarning) {
      return;
    }
    await api.updateSettings({
      cert_warning_days: thresholdWarning,
      cert_critical_days: thresholdCritical,
    });
    onSaved(thresholdWarning, thresholdCritical);
    onClose();
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal" role="document">
    <h2>Expiration Thresholds</h2>

    <div class="form-group">
      <label for="thresh-warn">Warning threshold (days)</label>
      <input id="thresh-warn" type="number" min="1" bind:value={thresholdWarning} />
      <span class="field-hint">Certificates expiring within this many days show orange.</span>
    </div>

    <div class="form-group">
      <label for="thresh-crit">Critical threshold (days)</label>
      <input id="thresh-crit" type="number" min="1" bind:value={thresholdCritical} />
      <span class="field-hint">Certificates expiring within this many days show red.</span>
    </div>

    {#if thresholdCritical >= thresholdWarning}
      <div class="form-error">Critical threshold must be less than warning threshold.</div>
    {/if}

    <div class="form-actions">
      <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
      <button class="btn btn-primary" disabled={thresholdCritical >= thresholdWarning} onclick={save}>Save</button>
    </div>
  </div>
</div>

<style>
  .form-error {
    background: var(--color-red-subtle);
    border: 1px solid var(--color-red);
    border-radius: var(--radius-md);
    color: var(--color-red);
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-base);
    margin-bottom: var(--space-4);
  }

  .form-group {
    margin-bottom: 1rem;
  }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: var(--sans);
  }

  .form-group input:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .field-hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.5rem;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
  }

  .btn-primary {
    background: var(--color-primary);
    color: white;
  }

  .btn-primary:hover {
    background: var(--color-primary-hover);
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }
</style>
