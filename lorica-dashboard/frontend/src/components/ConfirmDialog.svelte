<script lang="ts">
  interface Props {
    title: string;
    message: string;
    confirmLabel?: string;
    onconfirm: () => void;
    oncancel: () => void;
  }

  let { title, message, confirmLabel = 'Delete', onconfirm, oncancel }: Props = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      oncancel();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      onconfirm();
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="overlay" onclick={oncancel} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="dialog" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
    <h3>{title}</h3>
    <p>{message}</p>
    <div class="actions">
      <button class="btn btn-cancel" onclick={oncancel}>Cancel</button>
      <button class="btn btn-danger" onclick={onconfirm}>{confirmLabel}</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    max-width: 400px;
    width: 90%;
  }

  h3 {
    margin: 0 0 0.75rem;
  }

  p {
    color: var(--color-text-muted);
    margin: 0 0 1.25rem;
    font-size: 0.875rem;
    line-height: 1.5;
  }

  .actions {
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

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }

  .btn-danger {
    background: var(--color-red);
    color: white;
  }

  .btn-danger:hover {
    background: #dc2626;
  }
</style>
