<script lang="ts">
  import type { ManagedBy } from '../lib/api';
  import { managedBadgeTitle } from '../lib/managed-by';

  interface Props {
    managedBy: ManagedBy;
  }

  let { managedBy }: Props = $props();
</script>

<span class="automation-badge" title={managedBadgeTitle(managedBy)}>
  <span class="kind">automation</span>
  <span class="env">{managedBy.environment}</span>
</span>

<style>
  .automation-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.125rem 0.5rem;
    margin-left: var(--space-2);
    border-radius: var(--radius-full, 9999px);
    background: var(--color-primary-subtle);
    color: var(--color-primary);
    border: 1px solid var(--color-primary-subtle);
    font-size: var(--text-xs);
    font-weight: 600;
    white-space: nowrap;
    cursor: help;
  }

  .kind {
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .env {
    font-family: var(--font-mono, monospace);
    font-weight: 500;
  }
</style>
