<script lang="ts">
  import Nav from '../components/Nav.svelte';
  import Overview from './Overview.svelte';
  import Routes from './Routes.svelte';
  import Backends from './Backends.svelte';
  import Certificates from './Certificates.svelte';
  import Security from './Security.svelte';
  import Sla from './Sla.svelte';
  import Probes from './Probes.svelte';
  import LoadTest from './LoadTest.svelte';
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
    <Backends />
  {:else if path === '/certificates'}
    <Certificates />
  {:else if path === '/security'}
    <Security />
  {:else if path === '/sla'}
    <Sla />
  {:else if path === '/probes'}
    <Probes />
  {:else if path === '/loadtest'}
    <LoadTest />
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
