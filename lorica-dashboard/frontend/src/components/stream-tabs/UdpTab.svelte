<script lang="ts">
  import { UDP_SPECS, type StreamDraft, type UdpField } from '../../lib/stream-form';
  import FieldControl from './FieldControl.svelte';

  interface Props {
    draft: StreamDraft;
    creating: boolean;
  }

  let { draft = $bindable(), creating }: Props = $props();

  /** The bounds `unbounded_responses` suspends: they keep their values and apply again once it is cleared. */
  const RESPONSE_BOUNDS: ReadonlySet<UdpField> = new Set<UdpField>(['responses_per_request', 'response_bytes_ratio']);

  const SESSION: UdpField[] = ['max_sessions', 'source_session_cap', 'requests_per_session'];
  const RESPONSES: UdpField[] = ['unbounded_responses', 'responses_per_request', 'response_bytes_ratio'];
  const SOURCES: UdpField[] = ['source_datagram_rate', 'source_byte_rate', 'max_datagram_bytes'];

  const unbounded = $derived(draft.udp.unbounded_responses === true);
</script>

<div class="tab-content">
  <h3 class="subsection-title">Sessions</h3>
  {#each SESSION as key (key)}
    <FieldControl
      id="stream-udp-{key}"
      spec={UDP_SPECS[key]}
      bind:value={draft.udp[key]}
      {creating}
      disabled={key === 'requests_per_session' && draft.udpRequestsUnbounded}
    />
    {#if key === 'requests_per_session'}
      <label class="checkbox-item no-bound">
        <input type="checkbox" bind:checked={draft.udpRequestsUnbounded} />
        No bound on requests per session
      </label>
    {/if}
  {/each}

  <h3 class="subsection-title">Responses</h3>
  {#each RESPONSES as key (key)}
    <FieldControl
      id="stream-udp-{key}"
      spec={UDP_SPECS[key]}
      bind:value={draft.udp[key]}
      {creating}
      disabled={unbounded && RESPONSE_BOUNDS.has(key)}
    />
  {/each}
  {#if unbounded}
    <p class="hint">The two response bounds keep their values and apply again once unbounded responses is cleared.</p>
  {/if}

  <h3 class="subsection-title">Per source</h3>
  {#each SOURCES as key (key)}
    <FieldControl id="stream-udp-{key}" spec={UDP_SPECS[key]} bind:value={draft.udp[key]} {creating} />
  {/each}
</div>

<style>
  .subsection-title {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
  }
  .subsection-title:first-child {
    margin-top: 0;
  }
  .no-bound {
    margin: calc(-1 * var(--space-2)) 0 var(--space-4);
  }
</style>
