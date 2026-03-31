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
    border-radius: var(--radius-xl);
    padding: var(--space-5);
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    box-shadow: var(--shadow-sm);
    transition: box-shadow var(--transition-base), border-color var(--transition-base), transform var(--transition-fast);
  }

  .card:hover {
    box-shadow: var(--shadow-md);
    transform: translateY(-1px);
  }

  .card-title {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
  }

  .card-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--color-text-heading);
    font-family: var(--mono);
    letter-spacing: -0.02em;
  }

  .green {
    border-left: 3px solid var(--color-green);
  }
  .green .card-value { color: var(--color-green); }

  .orange {
    border-left: 3px solid var(--color-orange);
  }
  .orange .card-value { color: var(--color-orange); }

  .red {
    border-left: 3px solid var(--color-red);
  }
  .red .card-value { color: var(--color-red); }
</style>
