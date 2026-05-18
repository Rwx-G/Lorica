<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import Nav from '../components/Nav.svelte';
  import Placeholder from './Placeholder.svelte';
  import { currentPath } from '../lib/router';
  import { isDynamicImportError } from '../lib/chunk-reload';

  // Lazy-load each route component so Vite emits a separate chunk per
  // page. The login flow no longer pays for the admin code, and a
  // one-route edit no longer invalidates the entire dashboard bundle.
  // All components share the same () => import() shape so the loader
  // below is a single map instead of one branch per route.
  const routeLoaders: Record<string, () => Promise<{ default: Component }>> = {
    '/':            () => import('./Overview.svelte'),
    '/routes':      () => import('./Routes.svelte'),
    '/backends':    () => import('./Backends.svelte'),
    '/certificates':() => import('./Certificates.svelte'),
    '/security':    () => import('./Security.svelte'),
    '/sla':         () => import('./Sla.svelte'),
    '/probes':      () => import('./Probes.svelte'),
    '/loadtest':    () => import('./LoadTest.svelte'),
    '/logs':        () => import('./Logs.svelte'),
    '/system':      () => import('./System.svelte'),
    '/settings':    () => import('./Settings.svelte'),
  };

  let path = $state('/');
  let CurrentRoute: Component | null = $state(null);
  let loadError = $state<string | null>(null);

  // Stale-chunk recovery. When the operator upgrades Lorica while a
  // dashboard tab is open, the in-memory bundle still references the
  // old lazy-chunk hash for any route not yet visited in this session.
  // The new binary embeds different hashes, so the first navigation
  // into that route 404s with "error loading dynamically imported
  // module". We catch that one class of failure and force a single
  // reload to pick up the fresh index.html and its current chunk map.
  // A sessionStorage flag prevents a reload loop if the chunk is truly
  // missing for another reason (proxy bug, asset corruption); the flag
  // clears as soon as any route loads successfully again.
  const RELOAD_GUARD_KEY = 'lorica:chunk-reload';

  currentPath.subscribe((v) => {
    path = v;
  });

  async function loadRoute(p: string) {
    const loader = routeLoaders[p];
    if (!loader) {
      CurrentRoute = null;
      loadError = null;
      return;
    }
    try {
      const mod = await loader();
      CurrentRoute = mod.default;
      loadError = null;
      sessionStorage.removeItem(RELOAD_GUARD_KEY);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (
        isDynamicImportError(message) &&
        !sessionStorage.getItem(RELOAD_GUARD_KEY)
      ) {
        sessionStorage.setItem(RELOAD_GUARD_KEY, '1');
        window.location.reload();
        return;
      }
      loadError = message;
      CurrentRoute = null;
    }
  }

  onMount(() => {
    void loadRoute(path);
  });

  $effect(() => {
    void loadRoute(path);
  });
</script>

<Nav />
<main class="content">
  {#if loadError}
    <Placeholder title={`Failed to load: ${loadError}`} />
  {:else if CurrentRoute}
    <CurrentRoute />
  {:else if !routeLoaders[path]}
    <Placeholder title="Not Found" />
  {/if}
</main>

<style>
  .content {
    flex: 1;
    padding: var(--space-8) var(--space-10);
    overflow-y: auto;
    min-width: 0;
  }
</style>
