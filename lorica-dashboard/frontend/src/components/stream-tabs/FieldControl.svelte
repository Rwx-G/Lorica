<script lang="ts">
  import { labelOf, type DraftValue, type ScalarSpec } from '../../lib/stream-form';

  interface Props {
    /** The control's id, for its label. */
    id: string;
    spec: ScalarSpec;
    value: DraftValue;
    /** A create leaves a boolean or a choice to the server until it is picked. */
    creating: boolean;
    /** The options of a `choice` field. */
    choices?: { value: string; label: string }[];
    /** A choice the server requires has no "server default" option. */
    required?: boolean;
    disabled?: boolean;
  }

  let { id, spec, value = $bindable(), creating, choices = [], required = false, disabled = false }: Props = $props();

  const label = $derived(labelOf(spec));

  /** A create's boolean as a select: `''` is the server default. */
  function boolText(v: DraftValue): string {
    return v === null ? '' : v ? 'on' : 'off';
  }
</script>

<div class="form-group stream-field">
  {#if spec.kind === 'bool' && !creating}
    <label class="checkbox-item" for={id}>
      <input {id} type="checkbox" checked={value === true} {disabled} onchange={(e) => (value = e.currentTarget.checked)} />
      {label}
    </label>
  {:else}
    <label for={id}>{label}</label>
    {#if spec.kind === 'bool'}
      <select
        {id}
        {disabled}
        value={boolText(value)}
        onchange={(e) => {
          const v = e.currentTarget.value;
          value = v === '' ? null : v === 'on';
        }}
      >
        <option value="">Server default</option>
        <option value="on">On</option>
        <option value="off">Off</option>
      </select>
    {:else if spec.kind === 'choice'}
      <select
        {id}
        {disabled}
        value={value ?? ''}
        onchange={(e) => {
          const v = e.currentTarget.value;
          value = v === '' ? null : v;
        }}
      >
        {#if !required && (creating || value === null)}
          <option value="">Server default</option>
        {/if}
        {#each choices as c (c.value)}
          <option value={c.value}>{c.label}</option>
        {/each}
      </select>
    {:else if spec.kind === 'int' || spec.kind === 'optional'}
      <input {id} type="number" {disabled} placeholder={spec.empty ?? ''} bind:value />
    {:else if spec.kind === 'lines'}
      <textarea {id} rows="3" {disabled} placeholder={spec.empty ?? ''} bind:value></textarea>
    {:else}
      <input {id} type="text" {disabled} placeholder={spec.empty ?? ''} bind:value />
    {/if}
  {/if}
  {#if spec.help}<span class="hint">{spec.help}</span>{/if}
</div>

<style>
  .stream-field textarea {
    font-family: var(--mono);
  }
</style>
