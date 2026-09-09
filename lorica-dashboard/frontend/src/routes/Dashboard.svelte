<script lang="ts">
  import { onMount, type Component } from 'svelte';

  import { api } from '../lib/api';
  import {
    clusterStatus,
    breakGlassActive,
    fleetBadge,
    isClustered,
  } from '../lib/cluster';

  /** How often the fleet state is refreshed while a tab is open. */
  const CLUSTER_POLL_MS = 10_000;
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
    '/cluster':     () => import('./Cluster.svelte'),
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

  // The fleet state feeds the nav (which hides itself on a standalone
  // install), the header badge, the read-only banner, AND the auth
  // derivation that decides whether mutating controls are offered at
  // all. It is polled here, once, rather than by each consumer.
  async function refreshCluster() {
    const res = await api.getClusterStatus();
    if (res.data) clusterStatus.set(res.data);
  }

  onMount(() => {
    void loadRoute(path);
    void refreshCluster();
    const timer = setInterval(() => void refreshCluster(), CLUSTER_POLL_MS);
    return () => clearInterval(timer);
  });

  $effect(() => {
    void loadRoute(path);
  });
</script>

<Nav />
<main class="content">
  {#if $clusterStatus && isClustered($clusterStatus)}
    {@const badge = fleetBadge($clusterStatus)}
    <div class="fleet-bar">
      {#if badge}
        <span class="badge badge-{badge.tone}" title={badge.reason ?? ''}>
          {badge.label}
        </span>
      {/if}
      {#if $clusterStatus.role === 'follower' && !breakGlassActive($clusterStatus)}
        <span class="readonly">
          Read-only: this node follows {$clusterStatus.control_plane}. Changes
          made here would be replaced at the next apply.
        </span>
      {/if}
      {#if breakGlassActive($clusterStatus)}
        <span class="glass">
          Break-glass open: local edits are allowed and will be overwritten when
          the window closes.
        </span>
      {/if}
    </div>
  {/if}
  {#if loadError}
    <Placeholder title={`Failed to load: ${loadError}`} />
  {:else if CurrentRoute}
    <CurrentRoute />
  {:else if !routeLoaders[path]}
    <Placeholder title="Not Found" />
  {/if}
</main>

<style>
  .fleet-bar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
    padding: 0.5rem 1.5rem;
    border-bottom: 1px solid var(--border, #e5e7eb);
    font-size: 0.85rem;
  }
  .badge {
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    font-weight: 600;
  }
  .badge-ok {
    background: #dcfce7;
    color: #166534;
  }
  .badge-warning {
    background: #fef3c7;
    color: #92400e;
  }
  .readonly {
    color: var(--text-muted, #6b7280);
  }
  .glass {
    color: #92400e;
    font-weight: 600;
  }
  .content {
    flex: 1;
    padding: var(--space-8) var(--space-10);
    overflow-y: auto;
    min-width: 0;
  }
</style>
