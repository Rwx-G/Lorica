<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS, validateHostname } from '../../lib/route-form';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';

  interface Props {
    form: RouteFormState;
    editing: boolean;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), editing, importedFields }: Props = $props();

  let hostnameError = $state('');
  let activeHelp = $state<null | 'section:identity' | 'section:response_override' | 'hostname' | 'path_prefix' | 'hostname_aliases' | 'enabled' | 'websocket_enabled' | 'access_log_enabled' | 'redirect_to' | 'redirect_hostname' | 'return_status' | 'error_page_html'>(null);

  function handleHostnameBlur() {
    hostnameError = validateHostname(form.hostname);
  }

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
</script>

<div class="tab-content">
  <!-- ================== Identity ================== -->
  <section class="subsection">
    <SubsectionHeader
      title="Identity"
      description="Who this route is and which requests it matches."
      accent="blue"
      onhelp={() => { activeHelp = 'section:identity'; }}
    />
    <div class="subsection-body">

      <div class="form-group" class:modified={isModified('hostname')}>
        <label for="hostname">
          Hostname <span class="required">*</span>
          <FieldHelpButton fieldLabel="Hostname" onhelp={() => { activeHelp = 'hostname'; }} />
        </label>
        {#if isImported('hostname')}<span class="imported-badge">imported</span>{/if}
        <input id="hostname" type="text" bind:value={form.hostname} placeholder="example.com" onblur={handleHostnameBlur} />
        {#if hostnameError}
          <span class="field-error">{hostnameError}</span>
        {/if}
      </div>

      <div class="form-group" class:modified={isModified('path_prefix')}>
        <label for="path">
          Path prefix
          <FieldHelpButton fieldLabel="Path prefix" onhelp={() => { activeHelp = 'path_prefix'; }} />
        </label>
        {#if isImported('path_prefix')}<span class="imported-badge">imported</span>{/if}
        <input id="path" type="text" bind:value={form.path_prefix} placeholder="/" />
        <span class="hint">Longest-match wins when multiple routes share the same hostname.</span>
      </div>

      <div class="form-group" class:modified={isModified('hostname_aliases')}>
        <label for="hostname-aliases">
          Hostname aliases
          <FieldHelpButton fieldLabel="Hostname aliases" onhelp={() => { activeHelp = 'hostname_aliases'; }} />
        </label>
        {#if isImported('hostname_aliases')}<span class="imported-badge">imported</span>{/if}
        <input id="hostname-aliases" type="text" bind:value={form.hostname_aliases} placeholder="alias1.com, alias2.com" />
        <span class="hint">Additional hostnames routed to this same configuration. Comma-separated.</span>
      </div>

      {#if editing}
        <div class="form-group" class:modified={isModified('enabled')}>
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={form.enabled} />
            <span>Route enabled</span>
            <FieldHelpButton fieldLabel="Route enabled" onhelp={() => { activeHelp = 'enabled'; }} />
          </label>
          <span class="hint">Unticking takes the route out of service without deleting it.</span>
        </div>
      {/if}

      <div class="form-group" class:modified={isModified('websocket_enabled')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.websocket_enabled} />
          <span>WebSocket support</span>
          <FieldHelpButton fieldLabel="WebSocket support" onhelp={() => { activeHelp = 'websocket_enabled'; }} />
        </label>
        {#if isImported('websocket_enabled')}<span class="imported-badge">imported</span>{/if}
        <span class="hint">Forwards the Upgrade handshake transparently.</span>
      </div>

      <div class="form-group" class:modified={isModified('access_log_enabled')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.access_log_enabled} />
          <span>Access log enabled</span>
          <FieldHelpButton fieldLabel="Access log enabled" onhelp={() => { activeHelp = 'access_log_enabled'; }} />
        </label>
        {#if isImported('access_log_enabled')}<span class="imported-badge">imported</span>{/if}
        <span class="hint">Per-request log lines for this route.</span>
      </div>

    </div>
  </section>

  <!-- ================== Response override ================== -->
  <section class="subsection">
    <SubsectionHeader
      title="Response override"
      description="Short-circuit the proxy and answer directly. Maintenance mode is toggled from the Routes list."
      accent="pink"
      onhelp={() => { activeHelp = 'section:response_override'; }}
    />
    <div class="subsection-body">

      <div class="form-group" class:modified={isModified('redirect_to')}>
        <label for="redirect-to">
          Redirect to (full URL)
          <FieldHelpButton fieldLabel="Redirect to" onhelp={() => { activeHelp = 'redirect_to'; }} />
        </label>
        {#if isImported('redirect_to')}<span class="imported-badge">imported</span>{/if}
        <input id="redirect-to" type="text" bind:value={form.redirect_to} placeholder="https://example.com/legacy" />
        <span class="hint">
          Use when you want full control: force a specific scheme (http/https),
          optionally prepend a path prefix. 301 with your URL + request's path
          &amp; query appended.
        </span>
      </div>

      <div class="form-group" class:modified={isModified('redirect_hostname')}>
        <label for="redirect-hostname">
          Redirect to another host (canonical)
          <FieldHelpButton fieldLabel="Redirect to another host" onhelp={() => { activeHelp = 'redirect_hostname'; }} />
        </label>
        {#if isImported('redirect_hostname')}<span class="imported-badge">imported</span>{/if}
        <input id="redirect-hostname" type="text" bind:value={form.redirect_hostname} placeholder="e.g. example.com" />
        <span class="hint">
          Use for canonical-host redirects (e.g. <code>www.example.com</code> &rarr;
          <code>example.com</code>). Hostname-only; preserves the client's scheme
          and path. Automatic loop guard: no redirect when already on the target.
        </span>
      </div>

      <div class="form-group" class:modified={isModified('return_status')}>
        <label for="return-status">
          Return status
          <FieldHelpButton fieldLabel="Return status" onhelp={() => { activeHelp = 'return_status'; }} />
        </label>
        {#if isImported('return_status')}<span class="imported-badge">imported</span>{/if}
        <input id="return-status" type="number" min="100" max="599" bind:value={form.return_status} placeholder="e.g. 403, 404, 410" />
        <span class="hint">Respond with this status instead of proxying.</span>
      </div>

      <div class="form-group" class:modified={isModified('error_page_html')}>
        <label for="error-page-html">
          Custom error page HTML
          <FieldHelpButton fieldLabel="Custom error page HTML" onhelp={() => { activeHelp = 'error_page_html'; }} />
        </label>
        <textarea id="error-page-html" rows="6" bind:value={form.error_page_html}
          placeholder={'<html><body><h1>{{status}}</h1><p>{{message}}</p></body></html>'}></textarea>
        <span class="hint">Optional override of Lorica's built-in error page.</span>
      </div>

    </div>
  </section>
</div>

{#if activeHelp === 'section:identity'}
  <HelpModal title="Identity" onclose={() => { activeHelp = null; }}>
    <p>
      The <strong>Identity</strong> fields define what this route is and which
      incoming requests it serves.
    </p>
    <p>
      <strong>Hostname</strong> is the primary virtual host (matched against
      the <code>Host</code> header). <strong>Path prefix</strong> narrows the
      match to a sub-path. <strong>Aliases</strong> add extra hostnames that
      share this route's configuration.
    </p>
    <p>
      Operational toggles (Enabled, WebSocket, Access log) describe how the
      route behaves but do not change what it serves.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:response_override'}
  <HelpModal title="Response override" onclose={() => { activeHelp = null; }}>
    <p>
      These fields let the route answer a request <strong>without forwarding
      to any backend</strong>. Useful for redirects, deprecation notices,
      403 blocks, or maintenance pages.
    </p>
    <p>Evaluation order (first match wins):</p>
    <ol>
      <li>Maintenance mode (toggled from the Routes list) - 503 always.</li>
      <li><code>Return status</code> - responds with that HTTP code.</li>
      <li><code>Redirect to</code> - 301 with a full URL.</li>
      <li><code>Redirect to another host</code> - 301 with only the host changed.</li>
      <li>Otherwise proxy to the configured backends.</li>
    </ol>
    <p>
      When any response-override path is taken, <code>Custom error page HTML</code>
      (when set) renders instead of Lorica's built-in branded page.
    </p>
  </HelpModal>
{:else if activeHelp === 'hostname'}
  <HelpModal title="Hostname" onclose={() => { activeHelp = null; }}>
    <p>
      The virtual host Lorica matches against the incoming <code>Host</code>
      header. Required. Must be unique across routes; use aliases to add
      secondary hostnames.
    </p>
    <p>
      Exact match for plain hostnames (<code>example.com</code>); wildcard
      prefix supported (<code>*.example.com</code>). Case-insensitive.
    </p>
    <p>Nginx equivalent: <code>server_name example.com;</code></p>
  </HelpModal>
{:else if activeHelp === 'path_prefix'}
  <HelpModal title="Path prefix" onclose={() => { activeHelp = null; }}>
    <p>
      URL path prefix this route matches. Default <code>/</code> matches
      every request to the hostname.
    </p>
    <p>
      When multiple routes share a hostname, the <strong>longest prefix wins</strong>.
      For example <code>/api</code> beats <code>/</code> for a request to
      <code>/api/users</code>.
    </p>
    <p>
      Fine-grained per-path overrides (backend, cache, redirect, return
      status per path) are configured under <strong>Path Rules</strong>.
    </p>
  </HelpModal>
{:else if activeHelp === 'hostname_aliases'}
  <HelpModal title="Hostname aliases" onclose={() => { activeHelp = null; }}>
    <p>
      Additional hostnames that resolve to this same route. Comma-separated.
    </p>
    <p>
      Useful when multiple DNS entries front the same service:
      <code>www.example.com, example.com, example.org</code>.
    </p>
    <p>
      To <em>redirect</em> one alias to another (instead of sharing the route),
      use <strong>Redirect to another host</strong> in the Response override
      section.
    </p>
  </HelpModal>
{:else if activeHelp === 'enabled'}
  <HelpModal title="Route enabled" onclose={() => { activeHelp = null; }}>
    <p>
      Master switch. Unticking immediately stops routing to this configuration
      without deleting it; requests to the hostname return 404.
    </p>
    <p>
      Use this for planned decommissioning, cutovers, or pausing a route under
      investigation. For a gentler "out of service" response, use
      <strong>maintenance mode</strong> (toggled from the Routes list) which
      returns 503 with <code>Retry-After</code>.
    </p>
  </HelpModal>
{:else if activeHelp === 'websocket_enabled'}
  <HelpModal title="WebSocket support" onclose={() => { activeHelp = null; }}>
    <p>
      Allows the HTTP-to-WebSocket <code>Upgrade</code> handshake to flow
      through Lorica unchanged, so clients can establish bidirectional
      connections with the backend.
    </p>
    <p>
      When disabled, <code>Upgrade</code> headers are stripped and the
      request is proxied as plain HTTP.
    </p>
    <p>
      Required for Socket.IO, SignalR, GraphQL subscriptions over WS, bare
      WebSockets, and HTTP/2 WebSockets (RFC 8441).
    </p>
  </HelpModal>
{:else if activeHelp === 'access_log_enabled'}
  <HelpModal title="Access log enabled" onclose={() => { activeHelp = null; }}>
    <p>
      Writes one log line per request to this route (method, path, status,
      latency, backend, client IP). Useful for traffic analytics and
      troubleshooting.
    </p>
    <p>
      Format and destination are set globally in
      <strong>Settings &gt; Global Config</strong>
      (<code>--log-format</code> and <code>--log-file</code> on the CLI). This
      toggle only controls whether this <em>route</em> contributes to the log.
    </p>
    <p>
      Disable on very high-QPS routes where log volume would dominate disk
      I/O.
    </p>
  </HelpModal>
{:else if activeHelp === 'redirect_to'}
  <HelpModal title="Redirect to (full URL)" onclose={() => { activeHelp = null; }}>
    <p>
      301 redirect to the URL you paste. Accepts a scheme (<code>http://</code>
      or <code>https://</code>), a hostname, and optionally a base path. No
      backend is called. The request's path + query are appended to your URL.
    </p>
    <p><strong>Examples:</strong></p>
    <ul>
      <li>
        <code>https://new.com</code> + request <code>/foo?bar=1</code>
        <br>&rarr; <code>Location: https://new.com/foo?bar=1</code>
      </li>
      <li>
        <code>https://new.com/api</code> + request <code>/foo</code>
        <br>&rarr; <code>Location: https://new.com/api/foo</code>
        (path prefix prepended)
      </li>
      <li>
        <code>http://insecure.internal</code> on an HTTPS request
        <br>&rarr; <code>Location: http://insecure.internal/...</code>
        (scheme downgrades - use cautiously)
      </li>
    </ul>
    <p><strong>Use this when</strong>:</p>
    <ul>
      <li>You need to force a specific scheme regardless of the client's.</li>
      <li>You want to prepend a path (e.g. migrating to a sub-path).</li>
      <li>You are redirecting to a different TLD / domain.</li>
    </ul>
    <p><strong>No self-loop guard</strong>: if you point this at the same
    hostname the route serves, clients will be redirected forever. For
    canonical-host cleanup (<code>www &rarr; apex</code>), use
    <strong>Redirect to another host</strong> below instead - it has a loop
    guard built in.</p>
  </HelpModal>
{:else if activeHelp === 'redirect_hostname'}
  <HelpModal title="Redirect to another host (canonical)" onclose={() => { activeHelp = null; }}>
    <p>
      Lightweight 301 redirect that <strong>only changes the hostname</strong>.
      Scheme is preserved from the client's request (HTTP stays HTTP, HTTPS
      stays HTTPS); path + query are preserved as-is.
    </p>
    <p><strong>Examples:</strong></p>
    <ul>
      <li>
        <code>example.com</code> on request
        <code>https://www.example.com/foo?bar=1</code>
        <br>&rarr; <code>Location: https://example.com/foo?bar=1</code>
      </li>
      <li>
        Same rule, client comes via HTTP
        <br>&rarr; <code>Location: http://example.com/foo?bar=1</code>
        (scheme preserved)
      </li>
    </ul>
    <p><strong>Use this when</strong>:</p>
    <ul>
      <li>You want canonical-host enforcement (<code>www.x.com</code>
        &rarr; <code>x.com</code>, or vice-versa).</li>
      <li>You want to preserve whatever scheme the client came in on.</li>
      <li>You need an automatic loop guard: if the request already arrives
        on the target host, no redirect fires.</li>
    </ul>
    <p>
      Input must be a bare hostname (no scheme, no path). For scheme
      changes or path-prefixing, use <strong>Redirect to (full URL)</strong>
      above.
    </p>
    <p>
      Evaluated <em>before</em> <code>Redirect to</code> in the proxy chain.
      If both are set, this one wins.
    </p>
  </HelpModal>
{:else if activeHelp === 'return_status'}
  <HelpModal title="Return status" onclose={() => { activeHelp = null; }}>
    <p>
      Short-circuit the proxy and respond directly with this HTTP status
      code. The backend is not called.
    </p>
    <p>
      Common values:
    </p>
    <ul>
      <li><code>403</code> - block all traffic (e.g. geo-fenced or deprecated).</li>
      <li><code>404</code> - pretend the route does not exist.</li>
      <li><code>410</code> - resource permanently gone (discourages crawlers).</li>
      <li><code>301</code> / <code>302</code> - pair with <strong>Redirect to</strong>.</li>
    </ul>
    <p>
      The response body is rendered via the <strong>Custom error page HTML</strong>
      template if set, or Lorica's built-in branded error page otherwise.
    </p>
  </HelpModal>
{:else if activeHelp === 'error_page_html'}
  <HelpModal title="Custom error page HTML" onclose={() => { activeHelp = null; }}>
    <p>
      Custom HTML shown for error responses this route generates (maintenance
      503, upstream 502/504, WAF 403, rate-limit 429, GeoIP 403, mTLS 495/496,
      and optionally your <code>Return status</code>).
    </p>
    <p>
      Optional. Leave empty to keep Lorica's built-in branded error page
      (neutral, anti-fingerprint, 3-tier diagnostic layout).
    </p>
    <p>Two placeholders are substituted before the page is served:</p>
    <ul>
      <li><code>{"{{status}}"}</code> - numeric HTTP status.</li>
      <li><code>{"{{message}}"}</code> - short human-readable reason.</li>
    </ul>
    <p>
      Tip: keep the HTML self-contained (no external CSS / JS / images) so
      the page stays functional even when the backend is unreachable.
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

  .form-group { margin-bottom: 1rem; }
  .form-group:last-child { margin-bottom: 0.5rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label,
  .form-group .field-label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .required { color: var(--color-red); }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }

  .form-group input[type="text"],
  .form-group input[type="number"],
  .form-group select,
  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: inherit;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="number"]:focus,
  .form-group select:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .form-group textarea {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.8125rem;
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .hint { font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; }

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
