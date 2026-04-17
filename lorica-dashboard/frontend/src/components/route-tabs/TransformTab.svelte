<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';
  import ResponseRewriteTab from './ResponseRewriteTab.svelte';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  let activeHelp = $state<
    | null
    | 'section:request_headers'
    | 'section:response_headers'
    | 'section:cors'
    | 'section:path_rewrite'
    | 'section:body_rewrite'
    | 'section:compression'
    | 'compression_enabled'
    | 'path_rewrite_regex'
  >(null);

  function isModified(field: keyof RouteFormState): boolean {
    const def = ROUTE_DEFAULTS[field];
    const cur = form[field];
    if (Array.isArray(def) && Array.isArray(cur)) {
      return def.length !== cur.length || def.some((v, i) => v !== cur[i]);
    }
    return def !== cur;
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  // Setting Access-Control-* in the free-form Response headers block
  // clashes with the dedicated CORS subsection, which already emits
  // those headers when origins are configured. The merge is
  // last-write-wins so the result is order-dependent and surprising.
  // (Resolves UXUI.md finding #24.)
  let corsInResponseHeaders = $derived.by(() => {
    const hasCors = /(^|\n)\s*access-control-/i.test(form.response_headers);
    const corsConfigured = form.cors_allowed_origins.trim().length > 0;
    return hasCors && corsConfigured;
  });
</script>

<div class="tab-content">

  <!-- ============ Request headers ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Request headers"
      description="Add or remove headers on requests forwarded to the backend."
      accent="blue"
      onhelp={() => { activeHelp = 'section:request_headers'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('proxy_headers')}>
        <label for="proxy-headers">Custom proxy headers</label>
        {#if isImported('proxy_headers')}<span class="imported-badge">imported</span>{/if}
        <textarea id="proxy-headers" rows="4" bind:value={form.proxy_headers}
          placeholder={'X-Forwarded-For=$remote_addr\nX-Custom=value'}></textarea>
        <span class="hint">Format: <code>key=value</code>, one per line. Nginx: <code>proxy_set_header</code>.</span>
      </div>
      <div class="form-group" class:modified={isModified('proxy_headers_remove')}>
        <label for="proxy-headers-remove">Remove proxy headers</label>
        {#if isImported('proxy_headers_remove')}<span class="imported-badge">imported</span>{/if}
        <input id="proxy-headers-remove" type="text" bind:value={form.proxy_headers_remove} placeholder="X-Powered-By, Server" />
        <span class="hint">Comma-separated. Applied before custom headers above.</span>
      </div>
    </div>
  </section>

  <!-- ============ Response headers ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Response headers"
      description="Add or remove headers on responses sent back to the client."
      accent="purple"
      onhelp={() => { activeHelp = 'section:response_headers'; }}
    />
    <div class="subsection-body">
      {#if corsInResponseHeaders}
        <div class="warn-banner" role="note">
          <strong>CORS clash detected.</strong>
          You have CORS origins configured (subsection below) and
          <code>Access-Control-*</code> headers listed here.
          The response filter merges both with last-write-wins semantics, so the final
          headers are order-dependent. Configure CORS below and leave
          <code>Access-Control-*</code> out of this list.
        </div>
      {/if}
      <div class="form-group" class:modified={isModified('response_headers')}>
        <label for="response-headers">Custom response headers</label>
        {#if isImported('response_headers')}<span class="imported-badge">imported</span>{/if}
        <textarea id="response-headers" rows="4" bind:value={form.response_headers}
          placeholder={'X-Frame-Options=DENY\nCache-Control=no-store'}></textarea>
        <span class="hint">
          Format: <code>key=value</code>, one per line. Avoid <code>Access-Control-*</code> here - set them via the CORS subsection below.
        </span>
      </div>
      <div class="form-group" class:modified={isModified('response_headers_remove')}>
        <label for="response-headers-remove">Remove response headers</label>
        {#if isImported('response_headers_remove')}<span class="imported-badge">imported</span>{/if}
        <input id="response-headers-remove" type="text" bind:value={form.response_headers_remove} placeholder="X-Powered-By, Server" />
        <span class="hint">Comma-separated. Applied before custom headers above.</span>
      </div>
    </div>
  </section>

  <!-- ============ CORS ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="CORS"
      description="Cross-Origin Resource Sharing. Lorica emits the Access-Control-* headers automatically when origins are listed."
      accent="cyan"
      onhelp={() => { activeHelp = 'section:cors'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('cors_allowed_origins')}>
        <label for="cors-origins">Allowed origins</label>
        {#if isImported('cors_allowed_origins')}<span class="imported-badge">imported</span>{/if}
        <input id="cors-origins" type="text" bind:value={form.cors_allowed_origins} placeholder="https://example.com, https://app.example.com" />
        <span class="hint">Comma-separated. Use <code>*</code> for any origin (incompatible with credentials).</span>
      </div>
      <div class="form-row">
        <div class="form-group" class:modified={isModified('cors_allowed_methods')}>
          <label for="cors-methods">Allowed methods</label>
          {#if isImported('cors_allowed_methods')}<span class="imported-badge">imported</span>{/if}
          <input id="cors-methods" type="text" bind:value={form.cors_allowed_methods} placeholder="GET, POST, PUT, DELETE" />
        </div>
        <div class="form-group" class:modified={isModified('cors_max_age_s')}>
          <label for="cors-max-age">Max age (s)</label>
          {#if isImported('cors_max_age_s')}<span class="imported-badge">imported</span>{/if}
          <input id="cors-max-age" type="number" min="0" bind:value={form.cors_max_age_s} placeholder="No limit" />
        </div>
      </div>
    </div>
  </section>

  <!-- ============ Path rewrite ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Path rewrite"
      description="Rewrite the request path before forwarding to the backend. Strip / add prefix runs first; regex rewrite runs after."
      accent="orange"
      onhelp={() => { activeHelp = 'section:path_rewrite'; }}
    />
    <div class="subsection-body">
      <div class="form-row">
        <div class="form-group" class:modified={isModified('strip_path_prefix')}>
          <label for="strip-path">Strip path prefix</label>
          {#if isImported('strip_path_prefix')}<span class="imported-badge">imported</span>{/if}
          <input id="strip-path" type="text" bind:value={form.strip_path_prefix} placeholder="/api/v1" />
          <span class="hint">Removed from the request path before proxying.</span>
        </div>
        <div class="form-group" class:modified={isModified('add_path_prefix')}>
          <label for="add-path">Add path prefix</label>
          {#if isImported('add_path_prefix')}<span class="imported-badge">imported</span>{/if}
          <input id="add-path" type="text" bind:value={form.add_path_prefix} placeholder="/backend" />
          <span class="hint">Prepended after stripping.</span>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" class:modified={isModified('path_rewrite_pattern')}>
          <label for="rewrite-pattern">
            Regex rewrite pattern
            <FieldHelpButton fieldLabel="Regex rewrite pattern" onhelp={() => { activeHelp = 'path_rewrite_regex'; }} />
          </label>
          <input id="rewrite-pattern" type="text" bind:value={form.path_rewrite_pattern} placeholder="^/api/v1/(.*)" />
          <span class="hint">Rust regex syntax. Linear time, ReDoS-safe. Applied after strip/add.</span>
        </div>
        <div class="form-group" class:modified={isModified('path_rewrite_replacement')}>
          <label for="rewrite-replacement">Regex rewrite replacement</label>
          <input id="rewrite-replacement" type="text" bind:value={form.path_rewrite_replacement} placeholder="/v2/$1" />
          <span class="hint">Use <code>$1</code>, <code>$2</code> ... for capture groups.</span>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ Response body rewrite ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Response body rewrite"
      description="Pattern-based search/replace on the response body (text / JSON / HTML). Cannot be used together with caching."
      accent="pink"
      onhelp={() => { activeHelp = 'section:body_rewrite'; }}
    />
    <div class="subsection-body subsection-body-panel">
      <ResponseRewriteTab bind:form={form} {importedFields} />
    </div>
  </section>

  <!-- ============ Compression ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Compression"
      description="gzip / brotli encoding of responses that advertise a matching Accept-Encoding header."
      accent="teal"
      onhelp={() => { activeHelp = 'section:compression'; }}
    />
    <div class="subsection-body">
      <div class="form-group" class:modified={isModified('compression_enabled')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.compression_enabled} />
          <span>Enable compression</span>
          <FieldHelpButton fieldLabel="Enable compression" onhelp={() => { activeHelp = 'compression_enabled'; }} />
        </label>
        {#if isImported('compression_enabled')}<span class="imported-badge">imported</span>{/if}
      </div>
    </div>
  </section>
</div>

{#if activeHelp === 'section:request_headers'}
  <HelpModal title="Request headers" onclose={() => { activeHelp = null; }}>
    <p>
      Shapes the request Lorica sends to the backend. Use this to inject
      tracing metadata, strip leaked infrastructure headers, or set
      routing decorators the backend reads.
    </p>
    <p>
      Lorica already adds <code>X-Forwarded-For</code>,
      <code>X-Forwarded-Proto</code>, <code>X-Forwarded-Host</code>, and
      <code>X-Request-Id</code> by default - no need to set them here.
    </p>
    <p>
      Remove runs before Add, so if both remove and add the same header
      name, the end state is the value from Add.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:response_headers'}
  <HelpModal title="Response headers" onclose={() => { activeHelp = null; }}>
    <p>
      Shapes the response Lorica sends back to the client. Typical use:
      security headers (HSTS, CSP, X-Frame-Options), cache directives,
      branding.
    </p>
    <p>
      Security-header presets (HSTS, CSP, X-Frame-Options, etc.) are
      better configured under <strong>Security &gt; Security headers
      preset</strong> which ships curated defaults.
    </p>
    <p>
      Do NOT set <code>Access-Control-*</code> headers here - they are
      emitted by the CORS subsection below and a clash causes
      last-write-wins ambiguity.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:cors'}
  <HelpModal title="CORS" onclose={() => { activeHelp = null; }}>
    <p>
      When at least one origin is listed, Lorica emits the required
      <code>Access-Control-*</code> headers on every response and handles
      preflight <code>OPTIONS</code> requests automatically. No need to
      configure these manually.
    </p>
    <p>Emitted on the response:</p>
    <ul>
      <li><code>Access-Control-Allow-Origin</code> - echoes the client's
        <code>Origin</code> header when it matches one of the listed
        allowed origins.</li>
      <li><code>Access-Control-Allow-Methods</code> - the list you
        configure.</li>
      <li><code>Access-Control-Max-Age</code> - caches the preflight
        on the client.</li>
    </ul>
    <p>
      Using <code>*</code> for any origin disables credentials
      (<code>Access-Control-Allow-Credentials</code> is omitted) per the
      CORS spec.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:path_rewrite'}
  <HelpModal title="Path rewrite" onclose={() => { activeHelp = null; }}>
    <p>
      Rewrites the URL path before Lorica hands the request to the
      backend. Three-stage pipeline applied in this order:
    </p>
    <ol>
      <li><strong>Strip path prefix</strong> - removes the prefix from
        the incoming path.</li>
      <li><strong>Add path prefix</strong> - prepends the new prefix.</li>
      <li><strong>Regex rewrite</strong> - pattern match + substitution
        with capture groups.</li>
    </ol>
    <p>Typical use cases:</p>
    <ul>
      <li>Serving <code>/api/v1/users</code> externally while the
        backend exposes <code>/users</code> (strip
        <code>/api/v1</code>).</li>
      <li>Mounting a legacy backend under a new namespace (add
        <code>/v2</code>).</li>
      <li>Version rewriting: <code>^/api/v1/(.*)</code> -&gt;
        <code>/v2/$1</code>.</li>
    </ul>
  </HelpModal>
{:else if activeHelp === 'section:body_rewrite'}
  <HelpModal title="Response body rewrite" onclose={() => { activeHelp = null; }}>
    <p>
      Pattern-based find / replace on the bytes of the response body.
      Useful for cosmetic fixes (rewriting internal hostnames in HTML),
      URL migrations, or injecting snippets.
    </p>
    <p>Per rule you configure:</p>
    <ul>
      <li><strong>Pattern</strong> + <strong>Replacement</strong>.</li>
      <li><strong>is_regex</strong>: plain-text find/replace by default,
        or Rust regex when ticked.</li>
      <li><strong>max_replacements</strong>: cap per response (0 =
        unlimited). Protects against runaway matches on large pages.</li>
    </ul>
    <p>
      Globally you control <code>max_body_bytes</code> (responses bigger
      than this pass through unmodified) and
      <code>content_type_prefixes</code> (which MIME types to touch -
      default <code>text/</code> + <code>application/json</code>).
    </p>
    <p>
      <strong>Mutually exclusive with caching</strong>. If a rule exists
      AND the route has cache enabled, Lorica silently skips the rewrite
      to avoid serving stale rewritten bytes after a rule edit. Tracked
      in the backlog - will turn into an inline warn banner.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:compression'}
  <HelpModal title="Compression" onclose={() => { activeHelp = null; }}>
    <p>
      Lorica applies on-the-fly gzip (and brotli when the client supports
      it) to responses whose <code>Content-Type</code> matches text-like
      MIME types. Only fires when the client advertises a supported
      <code>Accept-Encoding</code> header.
    </p>
    <p>
      Already-compressed bodies (images, video, <code>.gz</code>
      downloads) are passed through unchanged. The backend's own
      <code>Content-Encoding</code> header wins if it is already set.
    </p>
    <p>
      Runs after <code>Response body rewrite</code> so rewrites operate
      on the uncompressed bytes, and after the final response has been
      buffered or streamed.
    </p>
  </HelpModal>
{:else if activeHelp === 'compression_enabled'}
  <HelpModal title="Enable compression" onclose={() => { activeHelp = null; }}>
    <p>
      Turn on to let Lorica compress eligible responses before sending
      them to the client. Off by default.
    </p>
    <p>
      Off is the safer choice for backends that already do their own
      compression (double-compressing is a waste of CPU and can trip up
      strict clients). On is the ergonomic choice for plain HTTP
      backends that serve large text responses.
    </p>
  </HelpModal>
{:else if activeHelp === 'path_rewrite_regex'}
  <HelpModal title="Regex rewrite" onclose={() => { activeHelp = null; }}>
    <p>
      Rust-flavour regex (<a href="https://docs.rs/regex">docs.rs/regex</a>)
      applied to the path AFTER <code>Strip path prefix</code> and
      <code>Add path prefix</code>.
    </p>
    <p><strong>Examples:</strong></p>
    <ul>
      <li>
        Pattern <code>^/api/v1/(.*)</code>, replacement <code>/v2/$1</code>
        <br>&rarr; <code>/api/v1/users</code> becomes <code>/v2/users</code>.
      </li>
      <li>
        Pattern <code>^/legacy/(.*)</code>, replacement <code>/$1</code>
        <br>&rarr; drops the <code>/legacy</code> prefix.
      </li>
    </ul>
    <p>
      The Rust regex engine is linear-time and ReDoS-safe - catastrophic
      backtracking cannot happen here. Invalid patterns are rejected at
      save time with a clear error message.
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

  /* Wraps an embedded tab component (ResponseRewriteTab etc.). The
     child paints its own content but has no outer padding, so we
     add comfortable breathing room around it. */
  .subsection-body-panel {
    padding: 0.75rem 0.875rem 1rem;
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
  .warn-banner code { background: rgba(0,0,0,0.08); padding: 0 0.25rem; border-radius: 2px; }

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

  .form-group input[type="text"],
  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input:focus { outline: none; border-color: var(--color-primary); }

  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    resize: vertical;
  }

  .form-group textarea:focus { outline: none; border-color: var(--color-primary); }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

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
