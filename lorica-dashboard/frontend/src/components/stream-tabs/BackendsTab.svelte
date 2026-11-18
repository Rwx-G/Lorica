<script lang="ts">
  import type { BackendResponse } from '../../lib/api';
  import type { StreamDraft } from '../../lib/stream-form';
  import LinkSet from './LinkSet.svelte';

  interface Props {
    draft: StreamDraft;
    backends: BackendResponse[];
    /** A TLS stream links its backends per rule, not at the stream level. */
    perRule: boolean;
  }

  let { draft = $bindable(), backends, perRule }: Props = $props();
</script>

<div class="tab-content">
  {#if perRule}
    {#if draft.rules.length === 0}
      <p class="hint">A TLS stream lists its backends per rule: add a rule on the TLS tab first.</p>
    {/if}
    {#each draft.rules as rule, i (i)}
      <section class="rule-links" aria-label="Backends of rule {rule.name || i + 1}">
        <h3>Rule {rule.name || `#${i + 1}`}</h3>
        <LinkSet
          idPrefix="stream-rule-{i}"
          {backends}
          bind:primaries={draft.rules[i].backend_ids}
          bind:backups={draft.rules[i].backup_backend_ids}
          bind:caps={draft.rules[i].backend_max_active}
        />
      </section>
    {/each}
  {:else}
    <LinkSet
      idPrefix="stream-links"
      {backends}
      bind:primaries={draft.backend_ids}
      bind:backups={draft.backup_backend_ids}
      bind:caps={draft.backend_max_active}
    />
    <p class="hint">
      A backend of a UDP stream serves no route and no TCP stream, and has its
      health check disabled. A local backend needs "Allow a local backend" on
      the Connection tab.
    </p>
  {/if}
</div>

<style>
  .rule-links {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-4);
  }
  .rule-links h3 {
    margin: 0 0 var(--space-3);
    font-size: var(--text-md);
  }
</style>
