<script lang="ts">
  interface Props {
    title: string;
    value: string | number;
    color?: 'default' | 'green' | 'orange' | 'red';
    tooltip?: string;
  }

  let { title, value, color = 'default', tooltip }: Props = $props();
</script>

<div class="card" class:green={color === 'green'} class:orange={color === 'orange'} class:red={color === 'red'} title={tooltip ?? ''}>
  <span class="card-title">{title}</span>
  <span class="card-value">{value}</span>
</div>

<style>
  .card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-xl);
    padding: var(--space-4) var(--space-5);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-1);
    box-shadow: var(--shadow-sm);
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
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-align: center;
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
