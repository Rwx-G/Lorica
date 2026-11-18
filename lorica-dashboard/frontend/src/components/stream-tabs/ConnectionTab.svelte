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
    'load_balancing',
    'connect_timeout_ms',
    'idle_timeout_s',
    'total_timeout_s',
    'max_connect_attempts',
    'backend_keepalive',
    'backend_keepalive_idle_s',
    'close_on_backend_down',
    'max_connections',
    'upload_rate_bps',
    'download_rate_bps',
    'proxy_protocol_send',
    'proxy_protocol_accept',
    'proxy_protocol_trusted_cidrs',
    'source_addresses',
    'allow_local_backend',
  ];
</script>

<div class="tab-content">
  {#if protocol === 'udp'}
    <p class="hint">A UDP stream takes the connection settings that have a meaning per session; its own are on the UDP tab.</p>
  {/if}
  <ScalarFields bind:draft keys={KEYS} {fields} {protocol} {creating} />
</div>
