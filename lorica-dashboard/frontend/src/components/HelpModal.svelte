<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    children: Snippet;
    onclose: () => void;
  }

  let { title, children, onclose }: Props = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      onclose();
    }
  }
</script>

<div
  class="overlay"
  onclick={(e) => { if (e.target === e.currentTarget) onclose(); }}
  onkeydown={handleKeydown}
  role="dialog"
  aria-modal="true"
  aria-label={title}
  tabindex="-1"
>
  <div class="dialog" role="document">
    <div class="dialog-header">
      <h3>{title}</h3>
      <button class="btn-close" onclick={onclose} aria-label="Close help">
        <!-- eslint-disable-next-line svelte/no-at-html-tags -->
        {@html closeIcon}
      </button>
    </div>
    <div class="dialog-body">
      {@render children()}
    </div>
    <div class="dialog-footer">
      <button class="btn btn-primary" onclick={onclose}>Got it</button>
    </div>
  </div>
</div>

<script lang="ts" module>
  const closeIcon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
</script>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 150;
    padding: 1rem;
  }

  .dialog {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    max-width: 560px;
    width: 100%;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
  }

  .dialog-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  .dialog-header h3 {
    margin: 0;
    font-size: 1rem;
    color: var(--color-text-heading);
  }

  .btn-close {
    background: transparent;
    border: none;
    color: var(--color-text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0.25rem;
    border-radius: 0.25rem;
  }

  .btn-close:hover {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .dialog-body {
    padding: 1.25rem 1.5rem;
    overflow-y: auto;
    flex: 1;
    color: var(--color-text);
    font-size: 0.875rem;
    line-height: 1.55;
  }

  :global(.dialog-body p) {
    margin: 0 0 0.75rem;
  }

  :global(.dialog-body p:last-child) {
    margin-bottom: 0;
  }

  :global(.dialog-body code) {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    padding: 0.05rem 0.3rem;
    border-radius: 0.25rem;
  }

  :global(.dialog-body pre) {
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    padding: 0.75rem;
    overflow-x: auto;
    font-size: 0.8125rem;
    line-height: 1.4;
    margin: 0.5rem 0;
  }

  :global(.dialog-body ul),
  :global(.dialog-body ol) {
    margin: 0.5rem 0;
    padding-left: 1.25rem;
  }

  :global(.dialog-body li) {
    margin-bottom: 0.25rem;
  }

  :global(.dialog-body a) {
    color: var(--color-primary);
    text-decoration: underline;
  }

  .dialog-footer {
    display: flex;
    justify-content: flex-end;
    padding: 0.75rem 1.5rem;
    border-top: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
    cursor: pointer;
  }

  .btn-primary {
    background: var(--color-primary);
    color: white;
  }

  .btn-primary:hover {
    background: var(--color-primary-hover, #2563eb);
  }
</style>
