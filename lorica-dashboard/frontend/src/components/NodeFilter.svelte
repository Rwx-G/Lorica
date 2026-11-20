<script lang="ts">
  import { api } from '../lib/api';
  import { canReadFleet } from '../lib/auth';
  import { ALL_FOLLOWERS, clusterStatus } from '../lib/cluster';

  interface Props {
    /** `''` for this node, `ALL_FOLLOWERS`, or a follower's node id. */
    value: string;
    /** Called with the new choice when the operator picks one. */
    onchange: (choice: string) => void;
    /**
     * Whether to offer every follower at once. Only the pages whose
     * rows fan in have that aggregate; the SLA page has none (a fleet
     * percentile is not a function of per-node percentiles).
     */
    offerAllFollowers?: boolean;
  }

  let { value, onchange, offerAllFollowers = false }: Props = $props();

  let names = $state<{ id: string; label: string }[]>([]);

  /** Whether the roster has been fetched, so it is fetched once. */
  let loaded = false;

  // Rendered only where `canReadFleet` holds (AC #5): an operator who
  // never clustered must not see a filter with one option in it, a
  // follower has no roster to list, and a Viewer's roster read is 403.
  //
  // `$clusterStatus` is read for its own sake: `canReadFleet` only
  // notifies when it flips, while the status store emits on every poll,
  // and that re-run is what retries a failed roster read. A component
  // that mounts before the first status read populates the same way.
  $effect(() => {
    void $clusterStatus;
    if (loaded || !$canReadFleet) return;
    loaded = true;
    void (async () => {
      const res = await api.listClusterNodes();
      if (!res.data) {
        loaded = false;
        return;
      }
      names = res.data
        .filter((n) => n.status !== 'revoked')
        .map((n) => ({ id: n.node_id, label: n.name }));
    })();
  });
</script>

{#if $canReadFleet}
  <select
    class="filter-select"
    aria-label="Filter by node"
    {value}
    onchange={(e) => onchange((e.currentTarget as HTMLSelectElement).value)}
  >
    <option value="">This node</option>
    {#if offerAllFollowers}
      <option value={ALL_FOLLOWERS}>All followers</option>
    {/if}
    {#each names as n (n.id)}
      <option value={n.id}>{n.label}</option>
    {/each}
  </select>
{/if}
