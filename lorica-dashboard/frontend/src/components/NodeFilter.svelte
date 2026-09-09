<script lang="ts">
  import { api } from '../lib/api';
  import { canWriteRole } from '../lib/auth';
  import { clusterStatus, isClustered } from '../lib/cluster';

  interface Props {
    /** Selected node id, or `''` for every node (or this node). */
    value: string;
    /** Called with the new node id (or `''`) when the operator picks one. */
    onchange: (nodeId: string) => void;
    /**
     * Whether `''` means every node. The SLA page has no fleet
     * aggregate (a fleet percentile is not a function of per-node
     * percentiles), so there `''` means THIS node and the label says
     * so.
     */
    allowAll?: boolean;
  }

  let { value, onchange, allowAll = true }: Props = $props();

  let names = $state<{ id: string; label: string }[]>([]);

  // Hidden entirely on a standalone install (AC #5): an operator who
  // never clustered must not see a filter with one option in it. Also
  // hidden from a Viewer, for whom the roster it lists is 403.
  const clustered = $derived(isClustered($clusterStatus) && $canWriteRole);

  /** Whether the roster has been fetched, so it is fetched once. */
  let loaded = false;

  // Driven by the store rather than by mount. `clusterStatus` starts
  // null and is filled by an async read, so a component that mounts
  // first would have returned early here and never populated: the
  // select would appear a moment later with "All nodes" as its only
  // option, on a real cluster, until the page was navigated away from
  // and back.
  $effect(() => {
    if (loaded || !isClustered($clusterStatus) || !$canWriteRole) return;
    loaded = true;
    void (async () => {
      const res = await api.listClusterNodes();
      if (!res.data) {
        // Retry on the next status change rather than leaving the
        // filter permanently empty on one failed read.
        loaded = false;
        return;
      }
      names = res.data
        .filter((n) => n.status !== 'revoked')
        .map((n) => ({ id: n.node_id, label: n.name }));
    })();
  });
</script>

{#if clustered}
  <select
    class="filter-select"
    aria-label="Filter by node"
    {value}
    onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
  >
    <option value="">{allowAll ? 'All nodes' : 'This node'}</option>
    {#each names as n (n.id)}
      <option value={n.id}>{n.label}</option>
    {/each}
  </select>
{/if}
