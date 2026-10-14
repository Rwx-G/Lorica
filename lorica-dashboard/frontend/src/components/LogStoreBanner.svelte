<script lang="ts">
  import type { LogStoreStatus } from '../lib/api';

  // `null` until the first status read lands: no banner on a guess.
  let { status }: { status: LogStoreStatus | null } = $props();
</script>

{#if status && !status.persisting}
  <div class="log-store-banner" role="alert">
    Audit trail, access logs and WAF events are not being persisted: {status.cause ??
      'cause unknown'}
  </div>
{/if}

<style>
  .log-store-banner {
    padding: 0.6rem 1rem;
    margin-bottom: 1rem;
    border-radius: 6px;
    background: #dc2626;
    color: #ffffff;
    font-weight: 600;
    font-size: 0.9rem;
  }
</style>
