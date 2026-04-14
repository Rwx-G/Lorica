<script lang="ts">
  interface Props {
    onChoice: (choice: 'never' | 'always' | 'once') => void;
    onDismiss: () => void;
  }

  let { onChoice, onDismiss }: Props = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onDismiss();
  }
</script>

<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onDismiss(); }} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal" role="document">
    <h2>Self-signed Certificate Generation</h2>
    <p class="pref-text">Self-signed certificates are useful for development and testing but should not be used in production. How would you like to handle this?</p>
    <div class="pref-actions">
      <button class="btn btn-cancel" onclick={() => onChoice('never')}>Never generate</button>
      <button class="btn btn-secondary" onclick={() => onChoice('once')}>Just this once</button>
      <button class="btn btn-primary" onclick={() => onChoice('always')}>Always allow</button>
    </div>
  </div>
</div>

<style>
  .pref-text {
    color: var(--color-text-muted);
    font-size: 0.875rem;
    line-height: 1.5;
    margin: 0 0 1.25rem;
  }

  .pref-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
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

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }
</style>
