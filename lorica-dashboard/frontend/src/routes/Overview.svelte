<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type StatusResponse } from '../lib/api';
  import Card from '../components/Card.svelte';

  let status: StatusResponse | null = $state(null);
  let error = $state('');

  onMount(async () => {
    const res = await api.getStatus();
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      status = res.data;
    }
  });
</script>

<div class="overview">
  <h1>Overview</h1>

  {#if error}
    <div class="error-banner">{error}</div>
  {:else if !status}
    <p class="loading">Loading...</p>
  {:else}
    <h2>Routes</h2>
    <div class="card-grid">
      <Card title="Total Routes" value={status.routes_count} />
    </div>

    <h2>Backends</h2>
    <div class="card-grid">
      <Card title="Total" value={status.backends_count} />
      <Card title="Healthy" value={status.backends_healthy} color="green" />
      <Card title="Degraded" value={status.backends_degraded} color="orange" />
      <Card title="Down" value={status.backends_down} color="red" />
    </div>

    <h2>Certificates</h2>
    <div class="card-grid">
      <Card title="Total" value={status.certificates_count} />
      <Card title="Expiring Soon" value={status.certificates_expiring_soon} color="orange" />
    </div>
  {/if}
</div>

<style>
  .overview {
    max-width: 900px;
  }

  h2 {
    margin-top: 1.5rem;
    margin-bottom: 0.75rem;
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
  }

  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 1rem;
  }

  .error-banner {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.5rem;
    color: var(--color-red);
    padding: 0.75rem 1rem;
  }

  .loading {
    color: var(--color-text-muted);
  }
</style>
