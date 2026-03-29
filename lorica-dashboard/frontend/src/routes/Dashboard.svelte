<script lang="ts">
  import Nav from '../components/Nav.svelte';
  import Overview from './Overview.svelte';
  import Routes from './Routes.svelte';
  import Certificates from './Certificates.svelte';
  import Logs from './Logs.svelte';
  import SystemView from './System.svelte';
  import Settings from './Settings.svelte';
  import Placeholder from './Placeholder.svelte';
  import { currentPath } from '../lib/router';

  let path = $state('/');

  currentPath.subscribe((v) => {
    path = v;
  });
</script>

<Nav />
<main class="content">
  {#if path === '/'}
    <Overview />
  {:else if path === '/routes'}
    <Routes />
  {:else if path === '/backends'}
    <Placeholder title="Backends" />
  {:else if path === '/certificates'}
    <Certificates />
  {:else if path === '/logs'}
    <Logs />
  {:else if path === '/system'}
    <SystemView />
  {:else if path === '/settings'}
    <Settings />
  {:else}
    <Placeholder title="Not Found" />
  {/if}
</main>

<style>
  .content {
    flex: 1;
    padding: 1.5rem 2rem;
    overflow-y: auto;
  }
</style>
