<script lang="ts">
  import type { AdcsUnsettledOutcome } from '../../lib/adcs-issuance';

  interface Props {
    /** An issuance answer that stored nothing. */
    outcome: AdcsUnsettledOutcome;
    testId: string;
  }

  let { outcome, testId }: Props = $props();
</script>

<div class="adcs-outcome" role="alert" data-testid={testId}>
  {#if outcome.kind === 'pending'}
    The authority answered that the request is pending, under request id
    <code>{outcome.requestId}</code>: {outcome.message}
    Nothing was stored. Templates that need CA manager approval are not
    supported; ask the authority's administrators about this request.
  {:else}
    {outcome.message}
  {/if}
</div>

<style>
  .adcs-outcome {
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.75rem;
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red);
    font-size: 0.8125rem;
    line-height: 1.45;
  }
  .adcs-outcome code {
    word-break: break-all;
  }
</style>
