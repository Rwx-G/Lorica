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

<span class="badge" class:healthy={status === 'healthy'} class:degraded={status === 'degraded'} class:down={status === 'down'} class:unknown={status === 'unknown'}>
  <span class="dot"></span>
  {labels[status] ?? 'Unknown'}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    white-space: nowrap;
  }

  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
  }

  .healthy {
    background: rgba(34, 197, 94, 0.1);
    color: var(--color-green);
  }
  .healthy .dot { background: var(--color-green); }

  .degraded {
    background: rgba(245, 158, 11, 0.1);
    color: var(--color-orange);
  }
  .degraded .dot { background: var(--color-orange); }

  .down {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }
  .down .dot { background: var(--color-red); }

  .unknown {
    background: rgba(148, 163, 184, 0.1);
    color: var(--color-text-muted);
  }
  .unknown .dot { background: var(--color-text-muted); }
</style>
