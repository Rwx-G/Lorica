<script lang="ts">
  interface Props {
    title: string;
  }

  let { title }: Props = $props();
</script>

<div class="placeholder">
  <h1>{title}</h1>
  <p>This section is not yet implemented.</p>
</div>

<style>
  .placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 300px;
    color: var(--color-text-muted);
  }

  h1 {
    color: var(--color-text-heading);
  }

  p {
    margin-top: 0.5rem;
  }
</style>
