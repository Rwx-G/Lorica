<script lang="ts">
  /**
   * A chip-based list input. Replaces "one entry per line" textareas
   * where each line is a well-shaped primitive (CIDR, ASN, domain).
   *
   * Each chip renders the raw value + a remove button. Invalid chips
   * get a red border + hover tooltip with the validator's error
   * message. New chips are added via Enter, comma, or the separator
   * string; pasted multi-line / multi-CSV input is split and added
   * as separate chips. Removing the last chip via Backspace works
   * when the input is empty (standard chip-input behaviour).
   *
   * `bind:value` stays a plain string (newline or comma separated)
   * so the parent tab's form state and the wire payload are
   * unchanged from the textarea version.
   *
   * Resolves UXUI.md finding #8.
   */

  interface Props {
    /** Bindable parent value - newline- or comma-separated. */
    value: string;
    /** How to join chips when writing back to `value`. */
    separator?: 'lines' | 'csv';
    /** Per-chip validator. Return null for valid, string for error. */
    validator?: (s: string) => string | null;
    /** Placeholder shown in the trailing input. */
    placeholder?: string;
    /** Label for screen readers; wired via aria-label. */
    ariaLabel?: string;
  }

  let {
    value = $bindable(''),
    separator = 'lines',
    validator,
    placeholder = 'Type and press Enter',
    ariaLabel,
  }: Props = $props();

  let draft = $state('');
  let inputEl: HTMLInputElement | undefined = $state();

  const sep = separator === 'csv' ? ', ' : '\n';
  const splitPattern = separator === 'csv' ? /[,\s]+/ : /[\r\n]+/;

  // chips derive from `value` so the parent can mutate it freely
  // (imports, undo, etc.) without fighting a local cache.
  let chips: string[] = $derived(
    value.split(splitPattern).map((s) => s.trim()).filter((s) => s.length > 0),
  );

  function writeBack(newChips: string[]) {
    value = newChips.join(sep);
  }

  function addChipsFromDraft() {
    if (draft.trim().length === 0) return;
    // Allow pasting multi-entry content in one shot: split on
    // separator pattern just like the parent does.
    const toAdd = draft
      .split(splitPattern)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (toAdd.length === 0) {
      draft = '';
      return;
    }
    writeBack([...chips, ...toAdd]);
    draft = '';
  }

  function removeChip(index: number) {
    writeBack(chips.filter((_, i) => i !== index));
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || (e.key === ',' && separator === 'csv')) {
      e.preventDefault();
      addChipsFromDraft();
    } else if (e.key === 'Backspace' && draft.length === 0 && chips.length > 0) {
      // Backspace on empty draft removes the last chip - classic
      // chip-input affordance.
      removeChip(chips.length - 1);
    }
  }

  function handleBlur() {
    // Commit a partially-typed chip on blur so operators who tab out
    // without pressing Enter do not lose their input.
    if (draft.trim().length > 0) addChipsFromDraft();
  }

  // Validation outcome per chip, computed lazily.
  let chipErrors: (string | null)[] = $derived(
    chips.map((c) => (validator ? validator(c) : null)),
  );
</script>

<div class="chip-list">
  <ul class="chips" role="list" aria-label={ariaLabel}>
    {#each chips as chip, i (i)}
      <li class="chip" class:invalid={chipErrors[i] !== null}>
        <span class="chip-label" title={chipErrors[i] ?? undefined}>{chip}</span>
        <button
          type="button"
          class="chip-remove"
          aria-label="Remove {chip}"
          onclick={() => removeChip(i)}
        >&times;</button>
      </li>
    {/each}
    <li class="chip-input-wrap">
      <input
        bind:this={inputEl}
        bind:value={draft}
        type="text"
        class="chip-input"
        placeholder={chips.length === 0 ? placeholder : ''}
        aria-label={ariaLabel ? `${ariaLabel} - new entry` : 'New entry'}
        onkeydown={handleKeydown}
        onblur={handleBlur}
      />
    </li>
  </ul>
  {#if chipErrors.some((e) => e !== null)}
    <p class="chip-errors" aria-live="polite">
      {chipErrors.filter((e) => e !== null).length} invalid {chipErrors.filter((e) => e !== null).length === 1 ? 'entry' : 'entries'}
      (hover the red chip for details).
    </p>
  {/if}
</div>

<style>
  .chip-list {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.375rem;
    padding: 0.375rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    list-style: none;
    margin: 0;
    min-height: 2.25rem;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.125rem 0.25rem 0.125rem 0.5rem;
    border-radius: 9999px;
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    font-size: 0.75rem;
    max-width: 100%;
  }

  .chip.invalid {
    border-color: var(--color-red, #ef4444);
    background: rgba(239, 68, 68, 0.08);
    color: var(--color-red, #ef4444);
  }

  .chip-label {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 20ch;
    cursor: help;
  }

  .chip-remove {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1rem;
    height: 1rem;
    padding: 0;
    border-radius: 9999px;
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    font-size: 0.875rem;
    line-height: 1;
    cursor: pointer;
  }

  .chip-remove:hover {
    background: rgba(0, 0, 0, 0.08);
    color: var(--color-text);
  }

  .chip.invalid .chip-remove:hover {
    background: rgba(239, 68, 68, 0.2);
    color: var(--color-red, #ef4444);
  }

  .chip-input-wrap {
    flex: 1 1 12ch;
    min-width: 12ch;
    display: flex;
  }

  .chip-input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 0.125rem 0.25rem;
    font-size: 0.8125rem;
    color: var(--color-text);
  }

  .chip-input:focus {
    outline: none;
  }

  .chip-errors {
    margin: 0;
    font-size: 0.6875rem;
    color: var(--color-red, #ef4444);
  }
</style>
