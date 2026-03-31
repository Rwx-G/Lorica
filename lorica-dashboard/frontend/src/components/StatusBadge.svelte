<script lang="ts">
  interface Props {
    status: 'healthy' | 'degraded' | 'down' | 'unknown';
  }

  let { status }: Props = $props();

  const labels: Record<string, string> = {
    healthy: 'Healthy',
    degraded: 'Degraded',
    down: 'Down',
    unknown: 'Unknown',
  };
</script>

<span class="status-badge" class:healthy={status === 'healthy'} class:degraded={status === 'degraded'} class:down={status === 'down'} class:unknown={status === 'unknown'}>
  <span class="dot"></span>
  {labels[status] ?? 'Unknown'}
</span>

<style>
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.125rem 0.625rem;
    border-radius: var(--radius-full);
    font-size: var(--text-sm);
    font-weight: 500;
    white-space: nowrap;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .healthy {
    background: var(--color-green-subtle);
    color: var(--color-green);
  }
  .healthy .dot {
    background: var(--color-green);
    box-shadow: 0 0 0 3px var(--color-green-subtle);
  }

  .degraded {
    background: var(--color-orange-subtle);
    color: var(--color-orange);
  }
  .degraded .dot {
    background: var(--color-orange);
    box-shadow: 0 0 0 3px var(--color-orange-subtle);
  }

  .down {
    background: var(--color-red-subtle);
    color: var(--color-red);
  }
  .down .dot {
    background: var(--color-red);
    box-shadow: 0 0 0 3px var(--color-red-subtle);
  }

  .unknown {
    background: rgba(100, 116, 139, 0.1);
    color: var(--color-text-muted);
  }
  .unknown .dot {
    background: var(--color-text-muted);
    box-shadow: 0 0 0 3px rgba(100, 116, 139, 0.15);
  }
</style>
