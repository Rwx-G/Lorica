<script lang="ts">
  import { api, type GenerateSelfSignedRequest } from '../../lib/api';

  interface Props {
    onClose: () => void;
    onReload: () => Promise<void>;
  }

  let { onClose, onReload }: Props = $props();

  let selfSignedDomain = $state('');
  let selfSignedError = $state('');
  let selfSignedSubmitting = $state(false);

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
  }

  async function handleSubmit() {
    if (!selfSignedDomain.trim()) {
      selfSignedError = 'Domain is required';
      return;
    }
    selfSignedSubmitting = true;
    selfSignedError = '';

    const body: GenerateSelfSignedRequest = {
      domain: selfSignedDomain,
    };
    const res = await api.generateSelfSigned(body);
    if (res.error) {
      selfSignedError = res.error.message;
      selfSignedSubmitting = false;
      return;
    }

    selfSignedSubmitting = false;
    onClose();
    await onReload();
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal" role="document">
    <h2>Generate Self-signed Certificate</h2>

    {#if selfSignedError}
      <div class="form-error">{selfSignedError}</div>
    {/if}

    <div class="form-group">
      <label for="selfsign-domain">Domain <span class="required">*</span></label>
      <input id="selfsign-domain" type="text" bind:value={selfSignedDomain} placeholder="localhost" />
    </div>

    <div class="form-actions">
      <button class="btn btn-cancel" onclick={onClose}>Cancel</button>
      <button class="btn btn-primary" disabled={selfSignedSubmitting} onclick={handleSubmit}>
        {selfSignedSubmitting ? 'Generating...' : 'Generate'}
      </button>
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

  .required {
    color: var(--color-red);
  }

  .form-group input[type="text"] {
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
