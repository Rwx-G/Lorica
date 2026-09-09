<script lang="ts">
  import { onMount } from 'svelte';

  import { api } from '../lib/api';
  import { clusterStatus, isClustered } from '../lib/cluster';

  interface Props {
    /** Selected node id, or `''` for every node. */
    value: string;
    /** Called with the new node id (or `''`) when the operator picks one. */
    onchange: (nodeId: string) => void;
  }

  let { value, onchange }: Props = $props();

  let names = $state<{ id: string; label: string }[]>([]);

  // Hidden entirely on a standalone install (AC #5): an operator who
  // never clustered must not see a filter with one option in it.
  const clustered = $derived(isClustered($clusterStatus));

  onMount(async () => {
    if (!isClustered($clusterStatus)) return;
    const res = await api.listClusterNodes();
    if (!res.data) return;
    names = res.data
      .filter((n) => n.node.status !== 'revoked')
      .map((n) => ({ id: n.node.node_id, label: n.node.name }));
  });
</script>

{#if clustered}
  <select
    class="filter-select"
    aria-label="Filter by node"
    {value}
    onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
  >
    <option value="">All nodes</option>
    {#each names as n (n.id)}
      <option value={n.id}>{n.label}</option>
    {/each}
  </select>
{/if}
