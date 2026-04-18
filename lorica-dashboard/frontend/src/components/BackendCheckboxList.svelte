<script lang="ts">
  import type { BackendResponse } from '../lib/api';
  import StatusBadge from './StatusBadge.svelte';

  interface Props {
    backends: BackendResponse[];
    selected: string[];
    onToggle: (id: string) => void;
    /** Show the health badge next to each entry. Default true. */
    showHealth?: boolean;
    /** Labelled-by target id for the group (accessibility). */
    ariaLabelledBy?: string;
    /** Empty-state message when no backends are known at all. */
    emptyMessage?: string;
    /** Minimum count before the search input appears. Default 6. */
    searchThreshold?: number;
  }

  let {
    backends,
    selected,
    onToggle,
    showHealth = true,
    ariaLabelledBy,
    emptyMessage = 'No backends available.',
    searchThreshold = 6,
  }: Props = $props();

  let query = $state('');

  function healthStatus(b: BackendResponse): 'healthy' | 'degraded' | 'down' | 'unknown' {
    if (b.health_status === 'healthy') return 'healthy';
    if (b.health_status === 'degraded') return 'degraded';
    if (b.health_status === 'down') return 'down';
    return 'unknown';
  }

  let showSearch = $derived(backends.length >= searchThreshold);

  let filtered = $derived.by(() => {
    if (!query.trim()) return backends;
    const q = query.trim().toLowerCase();
    return backends.filter(
      (b) =>
        (b.name ?? '').toLowerCase().includes(q) ||
        (b.group_name ?? '').toLowerCase().includes(q) ||
        (b.address ?? '').toLowerCase().includes(q),
    );
  });
</script>

{#if backends.length === 0}
  <p class="empty">{emptyMessage}</p>
{:else}
  {#if showSearch}
    <input
      class="search"
      type="text"
      bind:value={query}
      placeholder="Filter by name, group, or address..."
      aria-label="Filter backends"
    />
    {#if query.trim() && filtered.length === 0}
      <p class="empty">No backend matches &ldquo;{query}&rdquo;.</p>
    {/if}
  {/if}
  <div class="checkbox-list" role="group" aria-labelledby={ariaLabelledBy}>
    {#each filtered as b (b.id)}
      <label class="checkbox-item">
        <input
          type="checkbox"
          checked={selected.includes(b.id)}
          onchange={() => onToggle(b.id)}
        />
        <span class="backend-label">
          {b.name ? `${b.name} (${b.address})` : b.address}
          {#if b.group_name}
            <span class="group-tag">{b.group_name}</span>
          {/if}
        </span>
        {#if showHealth}
          <StatusBadge status={healthStatus(b)} />
        {/if}
      </label>
    {/each}
  </div>
  {#if query.trim() && filtered.length > 0 && filtered.length < backends.length}
    <span class="filter-summary">
      Showing <strong>{filtered.length}</strong> of {backends.length} backends.
      <button type="button" class="clear-btn" onclick={() => { query = ''; }}>Clear filter</button>
    </span>
  {/if}
{/if}

<style>
  .search {
    display: block;
    width: 100%;
    margin-bottom: 0.5rem;
    padding: 0.4rem 0.625rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .search:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    max-height: 150px;
    overflow-y: auto;
    padding: 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .backend-label {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
  }

  .group-tag {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 500;
    background: rgba(100, 116, 139, 0.15);
    color: var(--color-text-muted);
  }

  .empty {
    margin: 0.25rem 0;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
  }

  .filter-summary {
    display: block;
    margin-top: 0.375rem;
    font-size: 0.75rem;
    color: var(--color-text-muted);
  }

  .clear-btn {
    margin-left: 0.5rem;
    padding: 0;
    background: transparent;
    border: none;
    color: var(--color-primary);
    font-size: 0.75rem;
    cursor: pointer;
    text-decoration: underline;
  }
</style>
