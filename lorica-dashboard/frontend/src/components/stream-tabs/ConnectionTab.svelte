<script lang="ts">
  import type { StreamProtocol } from '../../lib/api';
  import { scalarsOn, type StreamDraft, type StreamField } from '../../lib/stream-form';
  import ScalarFields from './ScalarFields.svelte';

  interface Props {
    draft: StreamDraft;
    fields: ReadonlySet<StreamField>;
    protocol: StreamProtocol;
    creating: boolean;
  }

  let { draft = $bindable(), fields, protocol, creating }: Props = $props();

  const KEYS = scalarsOn('connection');
</script>

<div class="tab-content">
  {#if protocol === 'udp'}
    <p class="hint">A UDP stream takes the connection settings that have a meaning per session; its own are on the UDP tab.</p>
  {/if}
  <ScalarFields bind:draft keys={KEYS} {fields} {protocol} {creating} />
</div>
