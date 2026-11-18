<script lang="ts">
  import type { StreamProtocol } from '../../lib/api';
  import type { ScalarField, StreamDraft, StreamField } from '../../lib/stream-form';
  import CountryPicker from '../CountryPicker.svelte';
  import ScalarFields from './ScalarFields.svelte';

  interface Props {
    draft: StreamDraft;
    fields: ReadonlySet<StreamField>;
    protocol: StreamProtocol;
    creating: boolean;
  }

  let { draft = $bindable(), fields, protocol, creating }: Props = $props();

  const KEYS: ScalarField[] = [
    'source_allow_cidrs',
    'source_deny_cidrs',
    'source_max_connections',
    'max_pending_connections',
    'source_open_rate',
    'open_rate',
  ];
</script>

<div class="tab-content">
  <p class="hint">
    Judged before any byte is forwarded (TCP) or before a session is created
    (UDP), after the node's global connection filter and IP blocklist.
  </p>
  <ScalarFields bind:draft keys={KEYS} {fields} {protocol} {creating} />

  <div class="form-group">
    <label for="stream-geoip-mode">Country filter (GeoIP)</label>
    <select id="stream-geoip-mode" bind:value={draft.geoipMode}>
      <option value="">None</option>
      <option value="allowlist">Allow only the listed countries</option>
      <option value="denylist">Refuse the listed countries</option>
    </select>
    <span class="hint">A client whose country is unknown passes either way: this is not an address allowlist.</span>
  </div>
  {#if draft.geoipMode !== ''}
    <CountryPicker bind:value={draft.geoipCountries} label="Countries" />
  {/if}
</div>
