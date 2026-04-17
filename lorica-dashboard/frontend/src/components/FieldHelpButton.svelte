<script lang="ts">
  interface Props {
    fieldLabel: string;
    onhelp: () => void;
  }

  let { fieldLabel, onhelp }: Props = $props();
</script>

<button
  type="button"
  class="field-help-btn"
  onclick={onhelp}
  aria-label="Help on {fieldLabel}"
  title="What is this?"
>
  ?
</button>

<style>
  .field-help-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1rem;
    height: 1rem;
    padding: 0;
    margin-left: 0.375rem;
    border-radius: 9999px;
    border: 1px solid var(--color-border);
    background: var(--color-bg-card);
    color: var(--color-text-muted);
    font-size: 0.625rem;
    font-weight: 700;
    line-height: 1;
    cursor: pointer;
    vertical-align: middle;
  }

  .field-help-btn:hover {
    color: var(--color-primary);
    border-color: var(--color-primary);
  }
</style>
