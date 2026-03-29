<script lang="ts">
  interface Props {
    title: string;
    value: string | number;
    color?: 'default' | 'green' | 'orange' | 'red';
  }

  let { title, value, color = 'default' }: Props = $props();
</script>

<div class="card" class:green={color === 'green'} class:orange={color === 'orange'} class:red={color === 'red'}>
  <span class="card-title">{title}</span>
  <span class="card-value">{value}</span>
</div>

<style>
  .card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .card-title {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .card-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--color-text-heading);
  }

  .green .card-value { color: var(--color-green); }
  .orange .card-value { color: var(--color-orange); }
  .red .card-value { color: var(--color-red); }
</style>
