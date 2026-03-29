<script lang="ts">
  interface Props {
    notAfter: string;
    warningDays?: number;
    criticalDays?: number;
  }

  let { notAfter, warningDays = 30, criticalDays = 7 }: Props = $props();

  function getStatus(expiry: string, warn: number, crit: number): { label: string; css: string } {
    const now = Date.now();
    const exp = new Date(expiry).getTime();
    const daysLeft = Math.floor((exp - now) / 86_400_000);
    if (daysLeft < 0) return { label: 'Expired', css: 'expired' };
    if (daysLeft <= crit) return { label: `${daysLeft}d left`, css: 'critical' };
    if (daysLeft <= warn) return { label: `${daysLeft}d left`, css: 'warning' };
    return { label: 'Valid', css: 'valid' };
  }

  let status = $derived(getStatus(notAfter, warningDays, criticalDays));
</script>

<span class="badge {status.css}">
  <span class="dot"></span>
  {status.label}
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

  .valid {
    background: rgba(34, 197, 94, 0.1);
    color: var(--color-green);
  }
  .valid .dot { background: var(--color-green); }

  .warning {
    background: rgba(245, 158, 11, 0.1);
    color: var(--color-orange);
  }
  .warning .dot { background: var(--color-orange); }

  .critical {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }
  .critical .dot { background: var(--color-red); }

  .expired {
    background: rgba(239, 68, 68, 0.15);
    color: var(--color-red);
  }
  .expired .dot { background: var(--color-red); }
</style>
