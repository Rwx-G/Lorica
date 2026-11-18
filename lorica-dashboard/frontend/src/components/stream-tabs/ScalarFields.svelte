<script lang="ts">
  import type { StreamProtocol } from '../../lib/api';
  import {
    SCALAR_SPECS,
    choicesOf,
    type ScalarField,
    type StreamDraft,
    type StreamField,
  } from '../../lib/stream-form';
  import FieldControl from './FieldControl.svelte';

  interface Props {
    draft: StreamDraft;
    /** The fields of this tab, in display order. */
    keys: ScalarField[];
    /** What the stream takes (`fieldsFor`): a key outside it is not shown. */
    fields: ReadonlySet<StreamField>;
    protocol: StreamProtocol;
    creating: boolean;
  }

  let { draft = $bindable(), keys, fields, protocol, creating }: Props = $props();

  /** `protocol` has no server default: a create must name it. */
  const REQUIRED_CHOICES: ReadonlySet<ScalarField> = new Set<ScalarField>(['protocol']);
</script>

{#each keys.filter((k) => fields.has(k)) as key (key)}
  <FieldControl
    id="stream-{key}"
    spec={SCALAR_SPECS[key]}
    bind:value={draft.scalars[key]}
    {creating}
    choices={choicesOf(key, protocol)}
    required={REQUIRED_CHOICES.has(key)}
  />
{/each}
