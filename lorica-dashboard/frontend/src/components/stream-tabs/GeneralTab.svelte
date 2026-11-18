<script lang="ts">
  import type { StreamProtocol } from '../../lib/api';
  import type { ScalarField, StreamDraft, StreamField } from '../../lib/stream-form';
  import ScalarFields from './ScalarFields.svelte';

  interface Props {
    draft: StreamDraft;
    fields: ReadonlySet<StreamField>;
    protocol: StreamProtocol;
    creating: boolean;
  }

  let { draft = $bindable(), fields, protocol, creating }: Props = $props();

  const KEYS: ScalarField[] = [
    'name',
    'group_name',
    'protocol',
    'enabled',
    'listen_address',
    'port_first',
    'port_last',
    'node_selector',
  ];
</script>

<div class="tab-content">
  <ScalarFields bind:draft keys={KEYS} {fields} {protocol} {creating} />
  {#if !creating}
    <p class="hint">
      Switching the protocol resets the stream's protocol settings to the new
      protocol's defaults on save.
    </p>
  {/if}
</div>
