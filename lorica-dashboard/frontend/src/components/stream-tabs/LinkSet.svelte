<script lang="ts">
  import type { BackendResponse } from '../../lib/api';
  import BackendCheckboxList from '../BackendCheckboxList.svelte';

  interface Props {
    /** Unique per link set, for the controls' ids. */
    idPrefix: string;
    backends: BackendResponse[];
    primaries: string[];
    backups: string[];
    /** The cap of each capped link, by backend id; `null` or absent for none. */
    caps: Record<string, number | null>;
  }

  let { idPrefix, backends, primaries = $bindable(), backups = $bindable(), caps = $bindable() }: Props = $props();

  // A backend is a primary or a backup of one link set, never both: the
  // server refuses it, and picking one side drops the other.
  function togglePrimary(id: string) {
    primaries = primaries.includes(id) ? primaries.filter((b) => b !== id) : [...primaries, id];
    backups = backups.filter((b) => b !== id);
  }

  function toggleBackup(id: string) {
    backups = backups.includes(id) ? backups.filter((b) => b !== id) : [...backups, id];
    primaries = primaries.filter((b) => b !== id);
  }

  function nameOf(id: string): string {
    const b = backends.find((x) => x.id === id);
    return b ? `${b.name || b.address} (${b.address})` : id;
  }

  const linked = $derived([...primaries, ...backups]);
</script>

<div class="link-set">
  <div class="form-group">
    <span class="group-label" id="{idPrefix}-primaries">Primary backends</span>
    <BackendCheckboxList {backends} selected={primaries} onToggle={togglePrimary} ariaLabelledBy="{idPrefix}-primaries" />
  </div>
  <div class="form-group">
    <span class="group-label" id="{idPrefix}-backups">Backup backends</span>
    <BackendCheckboxList {backends} selected={backups} onToggle={toggleBackup} ariaLabelledBy="{idPrefix}-backups" />
    <span class="hint">Candidates only when no primary is.</span>
  </div>
  {#if linked.length > 0}
    <div class="caps">
      {#each linked as id (id)}
        <div class="form-group cap">
          <label for="{idPrefix}-cap-{id}">Max active to {nameOf(id)} (per node)</label>
          <input
            id="{idPrefix}-cap-{id}"
            type="number"
            placeholder="uncapped"
            value={caps[id] ?? ''}
            oninput={(e) => {
              const raw = e.currentTarget.value;
              caps = { ...caps, [id]: raw === '' ? null : Number(raw) };
            }}
          />
        </div>
      {/each}
      <span class="hint">The most connections or sessions the stream holds to that backend on each node; empty for no cap.</span>
    </div>
  {/if}
</div>

<style>
  .group-label {
    display: block;
    font-size: var(--text-base);
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: var(--space-1);
  }
  .caps {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 0 var(--space-4);
  }
  .caps .hint {
    grid-column: 1 / -1;
  }
</style>
