<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  let activeHelp = $state<
    | null
    | 'section:cache_config'
    | 'section:vary_headers'
    | 'cache_enabled'
    | 'cache_ttl_s'
    | 'cache_max_mb'
    | 'stale_while_revalidate_s'
    | 'stale_if_error_s'
    | 'cache_vary_headers'
  >(null);

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  // Caching and response body rewrite are mutually exclusive at the
  // proxy layer - the cache wins and rewrites are silently skipped
  // to avoid serving stale rewritten bytes after a rule edit. Warn
  // the operator before they save a combination that will no-op.
  // (Resolves UXUI.md finding #21.)
  let cacheRewriteClash = $derived(form.cache_enabled && form.response_rewrite_rules.length > 0);
</script>

<div class="tab-content">

  <!-- ============ Cache config ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Cache config"
      description="Response caching with TTL + stale serving. Mutually exclusive with response body rewrite - caching silently wins if both are configured."
      accent="cyan"
      onhelp={() => { activeHelp = 'section:cache_config'; }}
    />
    <div class="subsection-body">
      {#if cacheRewriteClash}
        <div class="warn-banner" role="note">
          <strong>Caching + response body rewrite are mutually exclusive.</strong>
          This route has response-rewrite rules configured (Transform &rarr; Response body rewrite).
          With caching on, rewrites are silently skipped so cached bytes do not drift from the active rules.
          Turn caching off or clear the rewrite rules to use either feature.
        </div>
      {/if}
      <div class="form-group" class:modified={isModified('cache_enabled')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.cache_enabled} />
          <span>Enable cache</span>
          <FieldHelpButton fieldLabel="Enable cache" onhelp={() => { activeHelp = 'cache_enabled'; }} />
        </label>
        {#if isImported('cache_enabled')}<span class="imported-badge">imported</span>{/if}
        <span class="hint">Off = every request hits the backend. Nginx: <code>proxy_cache</code>.</span>
      </div>

      <div class="form-row">
        <div class="form-group" class:modified={isModified('cache_ttl_s')}>
          <label for="cache-ttl">
            Cache TTL (s)
            <FieldHelpButton fieldLabel="Cache TTL" onhelp={() => { activeHelp = 'cache_ttl_s'; }} />
          </label>
          {#if isImported('cache_ttl_s')}<span class="imported-badge">imported</span>{/if}
          <input id="cache-ttl" type="number" min="1" bind:value={form.cache_ttl_s} placeholder="300" />
          <span class="hint">How long a response stays fresh before re-fetching.</span>
        </div>
        <div class="form-group" class:modified={isModified('cache_max_mb')}>
          <label for="cache-max-mb">
            Cache max size (MB)
            <FieldHelpButton fieldLabel="Cache max size" onhelp={() => { activeHelp = 'cache_max_mb'; }} />
          </label>
          {#if isImported('cache_max_mb')}<span class="imported-badge">imported</span>{/if}
          <input id="cache-max-mb" type="number" min="1" bind:value={form.cache_max_mb} placeholder="50" />
          <span class="hint">Hard cap on total cache footprint for this route.</span>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group" class:modified={isModified('stale_while_revalidate_s')}>
          <label for="stale-revalidate">
            Stale-while-revalidate (s)
            <FieldHelpButton fieldLabel="Stale-while-revalidate" onhelp={() => { activeHelp = 'stale_while_revalidate_s'; }} />
          </label>
          <input id="stale-revalidate" type="number" min="0" bind:value={form.stale_while_revalidate_s} placeholder="10" />
          <span class="hint">Serve stale content while refreshing in the background. 0 = off.</span>
        </div>
        <div class="form-group" class:modified={isModified('stale_if_error_s')}>
          <label for="stale-error">
            Stale-if-error (s)
            <FieldHelpButton fieldLabel="Stale-if-error" onhelp={() => { activeHelp = 'stale_if_error_s'; }} />
          </label>
          <input id="stale-error" type="number" min="0" bind:value={form.stale_if_error_s} placeholder="60" />
          <span class="hint">Serve stale content when the upstream returns an error. 0 = off.</span>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ Vary headers ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Vary headers"
      description="Partition the cache key by request header values so different clients (gzip vs identity, en vs fr) get separate cache entries."
      accent="purple"
      onhelp={() => { activeHelp = 'section:vary_headers'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('cache_vary_headers')}>
        <label for="cache-vary">
          Vary headers
          <FieldHelpButton fieldLabel="Vary headers" onhelp={() => { activeHelp = 'cache_vary_headers'; }} />
        </label>
        <input id="cache-vary" type="text" bind:value={form.cache_vary_headers} placeholder="Accept-Encoding, Accept-Language" />
        <span class="hint">Comma-separated request header names. Merged with the origin's <code>Vary</code> response header.</span>
      </div>
    </div>
  </section>
</div>

{#if activeHelp === 'section:cache_config'}
  <HelpModal title="Cache config" onclose={() => { activeHelp = null; }}>
    <p>
      Per-route response cache with TTL-based freshness and stale
      serving for availability during upstream failures or refresh
      windows.
    </p>
    <p>
      Lorica caches responses at the proxy layer. Cache hits return
      instantly without calling the backend; cache misses proxy
      normally and populate the cache on a 2xx response. Typical
      use: high-read low-write public APIs, static HTML pages,
      CDN-like behaviour for non-authenticated traffic.
    </p>
    <p>
      <strong>Interaction with Response body rewrite</strong>: mutually
      exclusive. If both are configured, Lorica silently skips the
      rewrite (to avoid serving stale rewritten bytes after a rule
      edit). Pick one.
    </p>
    <p>
      For finer cache control per path, use the <strong>Routing &gt;
      Path-based overrides</strong> subsection with cache-override on
      each path rule.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:vary_headers'}
  <HelpModal title="Vary headers" onclose={() => { activeHelp = null; }}>
    <p>
      Cache partitioning by request header values. Each listed header
      becomes part of the cache key so different client profiles get
      distinct cache entries.
    </p>
    <p>Typical use cases:</p>
    <ul>
      <li><code>Accept-Encoding</code> - serve a gzipped response only
        to clients that advertise gzip support (otherwise a plain
        identity client would receive encoded bytes it cannot
        decode).</li>
      <li><code>Accept-Language</code> - partition by language so en /
        fr / de get separate cache entries.</li>
      <li><code>Cookie</code> - avoid when possible (each unique
        cookie creates a cache entry; hit ratio collapses quickly).</li>
    </ul>
    <p>
      Merged with the origin's <code>Vary</code> response header, so
      an upstream that already advertises <code>Vary: Accept-Encoding</code>
      still gets correct cache partitioning even if this field is
      empty.
    </p>
  </HelpModal>
{:else if activeHelp === 'cache_enabled'}
  <HelpModal title="Enable cache" onclose={() => { activeHelp = null; }}>
    <p>
      Master switch for response caching on this route. Off = every
      request proxies to the backend unchanged.
    </p>
    <p>
      Turn on for read-heavy endpoints (public content, search
      results, product listings). Leave off for mutating endpoints
      (POST / PUT / DELETE), authenticated user data, or any response
      that must reflect a live backend state.
    </p>
    <p>
      Lorica caches only methods + statuses that are safe to cache
      per RFC 7234 (GET / HEAD with 200 / 203 / 204 / 206 / 300 /
      301 / 404 / 405 / 410 / 414 / 501). Other combinations always
      bypass the cache regardless of this toggle.
    </p>
  </HelpModal>
{:else if activeHelp === 'cache_ttl_s'}
  <HelpModal title="Cache TTL" onclose={() => { activeHelp = null; }}>
    <p>
      How long (in seconds) a cached response stays fresh before
      Lorica refetches it from the backend. After TTL expiry, the
      next request is a cache miss and repopulates the entry.
    </p>
    <p>
      Overridden when the backend sets its own cache directives
      (<code>Cache-Control: max-age=...</code>, <code>Expires</code>,
      <code>s-maxage</code>). Lorica picks the most specific directive
      per RFC 7234 precedence.
    </p>
    <p>
      Typical values: 60 s for hot data you can tolerate being a
      minute stale, 3600 s for daily reports, 86400 s for fully
      static content.
    </p>
  </HelpModal>
{:else if activeHelp === 'cache_max_mb'}
  <HelpModal title="Cache max size" onclose={() => { activeHelp = null; }}>
    <p>
      Hard cap on total cached bytes for this route (in megabytes).
      When the cache fills, Lorica evicts entries LRU-style until
      there is room.
    </p>
    <p>
      Size the cap to your working set: too small means thrash
      (every request pushes out another useful entry); too large
      means memory pressure. 10-100 MB per route is typical for
      text-heavy responses; 500-1000 MB for asset-heavy routes.
    </p>
  </HelpModal>
{:else if activeHelp === 'stale_while_revalidate_s'}
  <HelpModal title="Stale-while-revalidate" onclose={() => { activeHelp = null; }}>
    <p>
      Grace window (in seconds) after TTL expiry during which Lorica
      returns the stale cached response to the client AND kicks off
      a background refresh.
    </p>
    <p>
      The first client after expiry still gets a fast response (no
      latency spike on cache-miss) while the cache repopulates
      asynchronously. Subsequent requests within the window get
      either the fresh response (if refresh finished) or the same
      stale copy.
    </p>
    <p>
      Typical value: 10-60 s. Set to 0 to disable - every
      post-expiry request becomes a synchronous cache miss.
    </p>
  </HelpModal>
{:else if activeHelp === 'stale_if_error_s'}
  <HelpModal title="Stale-if-error" onclose={() => { activeHelp = null; }}>
    <p>
      Grace window (in seconds) during which Lorica serves the last
      known stale cached response when the upstream returns an
      error or is unreachable.
    </p>
    <p>
      Protects the client from transient upstream failures at the
      cost of serving slightly outdated data. The stale window
      starts at TTL expiry and extends for this duration.
    </p>
    <p>
      Typical value: 60-600 s. Long enough to ride out a backend
      restart or brief outage, short enough that clients do not see
      wildly outdated content on a long-running failure.
    </p>
  </HelpModal>
{:else if activeHelp === 'cache_vary_headers'}
  <HelpModal title="Vary headers" onclose={() => { activeHelp = null; }}>
    <p>
      Comma-separated request header names that partition the cache
      key for this route. Each unique combination of values becomes a
      distinct cache entry.
    </p>
    <p>
      Example: with <code>Accept-Encoding, Accept-Language</code>, a
      request with <code>gzip + fr</code> populates one entry and a
      request with <code>identity + en</code> populates another.
      Neither collides with nor overwrites the other.
    </p>
    <p>
      <strong>Cache-hit trade-off</strong>: adding a header
      multiplies the number of entries. Partition by
      <code>Accept-Encoding</code> almost always (cheap and
      correctness-critical). Partition by <code>Cookie</code> or
      <code>Authorization</code> almost never (hit ratio collapses
      toward zero).
    </p>
  </HelpModal>
{/if}

<style>
  .tab-content { display: flex; flex-direction: column; gap: 1.25rem; }

  .subsection {
    display: flex;
    flex-direction: column;
    border-radius: 0.5rem;
    overflow: hidden;
  }

  .subsection-body {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-top: none;
    border-radius: 0 0 0.5rem 0.5rem;
    padding: 1rem 1rem 0.5rem;
  }

  .warn-banner {
    margin-bottom: 1rem;
    padding: 0.5rem 0.75rem;
    background: rgba(245, 158, 11, 0.08);
    border-left: 3px solid var(--color-orange, #f59e0b);
    border-radius: 0 0.25rem 0.25rem 0;
    font-size: 0.8125rem;
    color: var(--color-text);
    line-height: 1.45;
  }
  .warn-banner strong { color: var(--color-text-heading); }

  .form-group { margin-bottom: 1rem; }
  .form-group:last-child { margin-bottom: 0.5rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="number"],
  .form-group input[type="text"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input:focus { outline: none; border-color: var(--color-primary); }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  .hint { display: block; font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; margin-top: 0.25rem; }

  .imported-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    margin-left: 0.375rem;
    vertical-align: middle;
  }
</style>
