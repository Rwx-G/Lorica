<script lang="ts">
  import { toasts, dismissToast } from '../lib/toast';

  let items: { id: number; message: string; type: string }[] = $state([]);

  toasts.subscribe((v) => {
    items = v;
  });
</script>

{#if items.length > 0}
  <div class="toast-container">
    {#each items as toast (toast.id)}
      <div class="toast toast-{toast.type}">
        <span class="toast-message">{toast.message}</span>
        <button class="toast-close" onclick={() => dismissToast(toast.id)} aria-label="Close">&times;</button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .toast-container {
    position: fixed;
    bottom: var(--space-4, 1rem);
    right: var(--space-4, 1rem);
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    pointer-events: none;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    min-width: 280px;
    max-width: 420px;
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    pointer-events: auto;
    animation: toast-slide-in 0.3s ease-out;
  }

  .toast-success {
    background: var(--color-green, #22c55e);
    color: #fff;
  }

  .toast-error {
    background: var(--color-red, #ef4444);
    color: #fff;
  }

  .toast-message {
    flex: 1;
  }

  .toast-close {
    background: none;
    border: none;
    color: inherit;
    font-size: 1.25rem;
    line-height: 1;
    cursor: pointer;
    opacity: 0.8;
    padding: 0;
  }

  .toast-close:hover {
    opacity: 1;
  }

  @keyframes toast-slide-in {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
</style>
