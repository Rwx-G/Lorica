<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type RouteProtectionRecord } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';
  import { canWrite } from '../../lib/auth';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
  }

  let { expanded, toggleSection }: Props = $props();

  let records = $state<RouteProtectionRecord[]>([]);
  let loading = $state(false);
  let loadError = $state('');

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    const res = await api.listRouteProtectionRecords();
    if (res.error) {
      loadError = res.error.message;
    } else if (res.data) {
      records = res.data.records;
    }
    loading = false;
  }

  onMount(load);

  // ---- Clear ----

  let clearing = $state<RouteProtectionRecord | null>(null);

  async function confirmClear(): Promise<void> {
    if (clearing === null) return;
    const id = clearing.id;
    clearing = null;
    const res = await api.clearRouteProtectionRecord(id);
    if (res.error) {
      showToast(res.error.message, 'error');
      return;
    }
    records = records.filter((record) => record.id !== id);
    showToast('Record cleared. Automation tokens may now serve these names without it.', 'success');
  }

  function names(record: RouteProtectionRecord): string[] {
    return [record.hostname, ...record.hostname_aliases];
  }

  function when(value: string): string {
    return new Date(value).toLocaleString();
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} aria-expanded={expanded} onclick={toggleSection}>
    <h2>Route Protection Records</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">
        When an automation token deletes a route that carries an access control
        a token may only strengthen, or moves it off a name (a new hostname, an
        alias dropped, a deeper path prefix), the node keeps a record of it over
        the names it released, listed here with the controls it holds. A route
        an automation token later creates or moves onto those names must carry
        them at least as strongly, or it is refused. A route you create or edit
        in the dashboard that is switched on and serves one of those names for
        the recorded path clears that name from its record. Clear a record only
        when its protections are no longer wanted.
      </p>

      {#if loadError}
        <div class="settings-form-error">{loadError}</div>
      {/if}
      {#if loading}
        <p class="settings-hint">Loading...</p>
      {/if}

      <div class="settings-table-wrap">
        <table class="settings-table">
          <thead>
            <tr>
              <th>Names</th>
              <th>Path</th>
              <th>Recorded controls</th>
              <th>Released by</th>
              <th>Released</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each records as record (record.id)}
              <tr>
                <td class="wrap-cell">
                  {#each names(record) as name (name)}
                    <code>{name}</code>
                  {/each}
                </td>
                <td><code>{record.path_prefix}</code></td>
                <td>
                  {#if record.readable}
                    {#each record.controls as control (control.fields.join('/'))}
                      <span class="badge badge-control" title={control.rule}>
                        {control.fields.join(' / ')}
                      </span>
                    {/each}
                  {:else}
                    <span class="badge badge-unreadable" title="This record refuses every automation route write that would serve its names until it is cleared.">
                      Unreadable
                    </span>
                  {/if}
                </td>
                <td>{record.deleted_by}</td>
                <td class="text-muted">{when(record.deleted_at)}</td>
                <td class="settings-actions-cell">
                  {#if $canWrite}
                    <button
                      class="settings-btn-action settings-btn-delete"
                      onclick={() => (clearing = record)}
                    >
                      Clear
                    </button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if records.length === 0 && !loading}
              <tr><td colspan="6" class="text-muted">No route protection records.</td></tr>
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
</section>

{#if clearing !== null}
  <ConfirmDialog
    title="Clear Route Protection Record"
    message={`Clear the record for ${names(clearing).join(', ')}? Automation tokens may then create a route on these names without the protections the recorded route carried. The clear is written to the audit log.`}
    confirmLabel="Clear"
    onconfirm={confirmClear}
    oncancel={() => (clearing = null)}
  />
{/if}

<style>
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 500;
    margin-right: 0.25rem;
    margin-bottom: 0.125rem;
  }
  .badge-control {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
    font-family: var(--mono);
  }
  .badge-unreadable {
    background: var(--color-red);
    color: white;
  }

  .wrap-cell code {
    display: block;
    font-family: var(--mono);
    font-size: 0.8125rem;
  }

  .text-muted {
    color: var(--color-text-muted);
    font-size: var(--text-xs);
  }
</style>
