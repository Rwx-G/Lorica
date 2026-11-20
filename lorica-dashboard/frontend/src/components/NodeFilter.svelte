<script lang="ts">
  import { api } from '../lib/api';
  import { canWriteRole } from '../lib/auth';
  import { ALL_FOLLOWERS, clusterStatus, isFleetView } from '../lib/cluster';

  interface Props {
    /** Selected node id, `''` for this node, or `ALL_FOLLOWERS`. */
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

  // Rendered only on a control plane (AC #5): an operator who never
  // clustered must not see a filter with one option in it, and a
  // follower has no roster to list, since only the control plane
  // serves it. Also hidden from a Viewer, for whom the roster is 403.
  const visible = $derived(isFleetView($clusterStatus) && $canWriteRole);

  /** Whether the roster has been fetched, so it is fetched once. */
  let loaded = false;

  // Driven by the store rather than by mount. `clusterStatus` starts
  // null and is filled by an async read, so a component that mounts
  // first would have returned early here and never populated: the
  // select would appear a moment later with this node as its only
  // option, on a real cluster, until the page was navigated away from
  // and back.
  $effect(() => {
    if (loaded || !visible) return;
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

{#if visible}
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
