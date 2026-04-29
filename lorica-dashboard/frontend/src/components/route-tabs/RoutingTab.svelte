<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import type { BackendResponse, CertificateResponse } from '../../lib/api';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import { findUncoveredHostnames } from '../../lib/cert-san-match';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';
  import BackendCheckboxList from '../BackendCheckboxList.svelte';
  import CanaryTab from './CanaryTab.svelte';
  import HeaderRulesTab from './HeaderRulesTab.svelte';
  import PathRulesTab from './PathRulesTab.svelte';
  import RoutingMirror from './RoutingMirror.svelte';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
    certificates: CertificateResponse[];
    importedFields?: Set<string>;
  }

  let { form = $bindable(), backends, certificates, importedFields }: Props = $props();

  const loadBalancingOptions = [
    { value: 'round_robin', label: 'Weighted Round Robin' },
    { value: 'consistent_hash', label: 'Consistent Hash' },
    { value: 'random', label: 'Random' },
    { value: 'peak_ewma', label: 'Peak EWMA' },
    { value: 'least_conn', label: 'Least Connections' },
  ];

  let activeHelp = $state<
    | null
    | 'section:default_backends'
    | 'section:traffic_splits'
    | 'section:header_rules'
    | 'section:path_rules'
    | 'section:mirror'
    | 'backend_ids'
    | 'certificate_id'
    | 'load_balancing'
    | 'force_https'
    | 'sticky_session'
  >(null);

  function toggleBackend(id: string) {
    if (form.backend_ids.includes(id)) {
      form.backend_ids = form.backend_ids.filter((b) => b !== id);
    } else {
      form.backend_ids = [...form.backend_ids, id];
    }
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

  // Sticky session + traffic split can contradict: sticky pins a
  // client via LORICA_SRV cookie, traffic splits route by IP hash.
  // A returning client with a sticky cookie may land on a backend
  // outside the canary bucket their IP was assigned to.
  // (Resolves UXUI.md finding #25.)
  let stickyVsSplitClash = $derived(form.sticky_session && form.traffic_splits.length > 0);

  // Cross-check the selected certificate's SAN list against the
  // route's hostname + aliases (RFC 6125 strict matching, the same
  // rules browsers enforce on the live handshake). A mismatch here
  // predicts a real TLS handshake error in production - flagged as
  // a non-blocking warning so a wildcard or multi-SAN cert that the
  // operator knows covers the host can still be saved without
  // friction. Resolves issue #11.
  let selectedCert = $derived<CertificateResponse | undefined>(
    form.certificate_id ? certificates.find((c) => c.id === form.certificate_id) : undefined,
  );
  let routeHostnames = $derived(
    [
      form.hostname,
      ...form.hostname_aliases.split(/[,\n]/).map((s) => s.trim()),
    ].filter((s) => s.length > 0),
  );
  let uncoveredByCert = $derived(
    selectedCert ? findUncoveredHostnames(routeHostnames, selectedCert.san_domains) : [],
  );
</script>

<div class="tab-content">

  <!-- Evaluation order banner. Resolves finding #23. The visible
       order of subsections below is INVERSE of evaluation order:
       foundation (Default, eval step 4) first, overrides going up
       to the first-evaluated Header-based routes. The number badge
       on each section's header shows the actual evaluation step. -->
  <div class="eval-order-banner" role="note">
    <strong>Evaluation order:</strong>
    Header-based routes (<span class="step">1</span>) &rarr; Traffic splits (<span class="step">2</span>) &rarr; Path-based overrides (<span class="step">3</span>) &rarr; Default backends (<span class="step">4</span>).
    First match wins.
  </div>

  <!-- ============ Default backends (eval step 4, foundation) ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Default backends"
      description="The primary backend pool, TLS termination, and how requests are distributed when no header / path / traffic-split rule matches. Foundation of this route."
      accent="green"
      order={4}
      orderLabel="Evaluated 4th (fallback). Runs when no other rule matches."
      onhelp={() => { activeHelp = 'section:default_backends'; }}
    />
    <div class="subsection-body">

      <div class="form-group">
        <label id="default-backends-label">
          <span>Backends</span>
          <FieldHelpButton fieldLabel="Backends" onhelp={() => { activeHelp = 'backend_ids'; }} />
        </label>
        {#if isImported('backend_ids')}<span class="imported-badge">imported</span>{/if}
        <BackendCheckboxList
          {backends}
          selected={form.backend_ids}
          onToggle={toggleBackend}
          ariaLabelledBy="default-backends-label"
          emptyMessage="No backends available - create one first in the Backends page."
        />
        <span class="hint">Tick every backend this route may use. Tick 2+ for redundancy + load balancing.</span>
      </div>

      <div class="form-group" class:modified={isModified('certificate_id')}>
        <label for="certificate">
          TLS Certificate
          <FieldHelpButton fieldLabel="TLS Certificate" onhelp={() => { activeHelp = 'certificate_id'; }} />
        </label>
        {#if isImported('certificate_id')}<span class="imported-badge">imported</span>{/if}
        <select id="certificate" bind:value={form.certificate_id} onchange={() => { if (!form.certificate_id) form.force_https = false; }}>
          <option value="">None (no TLS)</option>
          {#each certificates as c (c.id)}
            <option value={c.id}>{c.domain}</option>
          {/each}
        </select>
        <span class="hint">TLS certificate presented to clients on port 443 for this hostname.</span>
        {#if selectedCert && uncoveredByCert.length > 0}
          <div class="warn-banner" role="note">
            <strong>
              Certificate does not cover {uncoveredByCert.length === 1 ? 'this hostname' : 'these hostnames'}:
            </strong>
            {uncoveredByCert.join(', ')}.
            Clients reaching the route over HTTPS will see a TLS
            handshake error (SAN mismatch). Pick a cert whose SAN list
            includes the hostname (or a wildcard that covers it).
            Cert SAN list:
            {selectedCert.san_domains.length > 0 ? selectedCert.san_domains.join(', ') : '(empty)'}.
          </div>
        {/if}
      </div>

      <div class="form-group" class:modified={isModified('load_balancing')}>
        <label for="lb">
          Load Balancing
          <FieldHelpButton fieldLabel="Load Balancing" onhelp={() => { activeHelp = 'load_balancing'; }} />
        </label>
        {#if isImported('load_balancing')}<span class="imported-badge">imported</span>{/if}
        <select id="lb" bind:value={form.load_balancing}>
          {#each loadBalancingOptions as opt (opt.value)}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
        <span class="hint">Algorithm used to pick one backend per request when several are configured.</span>
      </div>

      <div class="form-group" class:modified={isModified('force_https')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.force_https} disabled={!form.certificate_id} />
          <span>Force HTTPS redirect</span>
          <FieldHelpButton fieldLabel="Force HTTPS redirect" onhelp={() => { activeHelp = 'force_https'; }} />
        </label>
        {#if !form.certificate_id}<span class="hint">Requires a TLS certificate to be selected.</span>{/if}
        {#if isImported('force_https')}<span class="imported-badge">imported</span>{/if}
      </div>

      <div class="form-group" class:modified={isModified('sticky_session')}>
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={form.sticky_session} />
          <span>Sticky sessions</span>
          <FieldHelpButton fieldLabel="Sticky sessions" onhelp={() => { activeHelp = 'sticky_session'; }} />
        </label>
        <span class="hint">Pins a client to the same backend via a LORICA_SRV cookie.</span>
        {#if stickyVsSplitClash}
          <div class="warn-banner" role="note">
            <strong>Sticky sessions conflict with traffic splits.</strong>
            A returning client with a LORICA_SRV cookie may land on a
            backend outside the split bucket their IP was hashed into.
            Turn off sticky sessions when running a fair canary.
          </div>
        {/if}
      </div>

    </div>
  </section>

  <!-- ============ Header-based routes (eval step 1, top priority) ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Header-based routes"
      description="Route by request header value (exact / prefix / regex) to alternate backend pools. First to evaluate; overrides every other routing decision below."
      accent="purple"
      order={1}
      orderLabel="Evaluated 1st. First match wins and short-circuits everything else."
      onhelp={() => { activeHelp = 'section:header_rules'; }}
    />
    <div class="subsection-body subsection-body-panel">
      <HeaderRulesTab bind:form={form} {backends} {importedFields} />
    </div>
  </section>

  <!-- ============ Traffic splits - canary (eval step 2) ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Traffic splits"
      description="Weighted canary distribution across the Default backends (see above) and alternate backend pools. Sticky per client IP."
      accent="cyan"
      order={2}
      orderLabel="Evaluated 2nd. Runs after header-based routes, before path-based overrides."
      onhelp={() => { activeHelp = 'section:traffic_splits'; }}
    />
    <div class="subsection-body subsection-body-panel">
      <CanaryTab bind:form={form} {backends} {importedFields} />
    </div>
  </section>

  <!-- ============ Path-based overrides (eval step 3) ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Path-based overrides"
      description="Per-path backend / cache / headers / rate-limit / redirect / return-status overrides. Evaluated after header-rules and traffic splits."
      accent="orange"
      order={3}
      orderLabel="Evaluated 3rd. Runs after header-based routes and traffic splits."
      onhelp={() => { activeHelp = 'section:path_rules'; }}
    />
    <div class="subsection-body subsection-body-panel">
      <PathRulesTab bind:form={form} {backends} {importedFields} />
    </div>
  </section>

  <!-- ============ Shadow / Mirror (parallel, not in eval chain) ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Shadow / Mirror"
      description="Fire-and-forget copy of every request to alternate backends. Runs in parallel with the primary routing decision. Responses discarded. Useful for shadow-testing a new version."
      accent="slate"
      order="//"
      orderLabel="Runs in parallel with the primary routing decision. Not part of the first-match chain."
      onhelp={() => { activeHelp = 'section:mirror'; }}
    />
    <div class="subsection-body">
      <RoutingMirror bind:form={form} {backends} />
    </div>
  </section>
</div>

{#if activeHelp === 'section:default_backends'}
  <HelpModal title="Default backends" onclose={() => { activeHelp = null; }}>
    <p>
      The <strong>primary backend pool</strong> serves every request that is
      not short-circuited by a redirect, captured by a header / path /
      traffic-split rule, or blocked by access control.
    </p>
    <p>
      Configure <em>who</em> receives traffic (Backends), <em>how</em>
      requests are distributed across them (Load Balancing), the TLS
      termination cert, HTTP-to-HTTPS redirection, and optional client
      affinity (Sticky sessions).
    </p>
  </HelpModal>
{:else if activeHelp === 'section:traffic_splits'}
  <HelpModal title="Traffic splits (canary)" onclose={() => { activeHelp = null; }}>
    <p>
      Deterministic weighted distribution of incoming traffic to alternate
      backend pools. Client affinity is sticky per source IP so a given
      client always hits the same bucket.
    </p>
    <p>Typical use cases:</p>
    <ul>
      <li><strong>Canary release</strong> - 5 % of traffic to the new
        backend version, 95 % to the stable one.</li>
      <li><strong>Blue/green cutover</strong> - flip from 100/0 to 0/100
        over a few saves.</li>
      <li><strong>A/B tests</strong> - 50/50 to two backends with the
        same contract but different implementations.</li>
    </ul>
    <p>
      Each split declares a weight percent and a backend pool. The sum of
      weights must not exceed 100 - the remainder routes to the Default
      backends section above. Sticky sessions (Default backends subsection)
      can pin a client outside the split they belong to; keep sticky off
      when running a fair canary.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:header_rules'}
  <HelpModal title="Header-based routes" onclose={() => { activeHelp = null; }}>
    <p>
      Route a request to an alternate backend pool when a specific header
      matches a rule. First match wins; evaluated <strong>before</strong>
      traffic splits and path-based overrides.
    </p>
    <p>Match types:</p>
    <ul>
      <li><strong>Exact</strong> - header value equals the rule value
        byte-for-byte.</li>
      <li><strong>Prefix</strong> - header value starts with the rule
        value.</li>
      <li><strong>Regex</strong> - header value matches a full-line
        regex. Invalid regex disables the rule; a "disabled" pill shows.</li>
    </ul>
    <p>
      Typical use cases: multi-tenant routing by <code>X-Tenant-Id</code>,
      API versioning by <code>X-Version</code>, feature flags by a client
      header, routing by <code>User-Agent</code> for legacy browsers.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:path_rules'}
  <HelpModal title="Path-based overrides" onclose={() => { activeHelp = null; }}>
    <p>
      Per-path overrides that apply after the backend pool is selected
      (by default / header-rule / traffic-split) and before the upstream
      call. Each rule declares a path match (prefix or exact) and any
      subset of these overrides:
    </p>
    <ul>
      <li><strong>Backend override</strong> - send matching requests to a
        different pool.</li>
      <li><strong>Cache override</strong> - force caching on/off for this
        path with a custom TTL.</li>
      <li><strong>Response headers</strong> - add or remove headers on
        responses from this path.</li>
      <li><strong>Rate limiting</strong> - per-path token bucket (RPS
        and burst).</li>
      <li><strong>Redirect</strong> - 301 redirect for this path.</li>
      <li><strong>Return status</strong> - respond with a fixed status
        without calling the backend.</li>
    </ul>
    <p>
      Rules are evaluated in order (drag to reorder). First match wins.
      Empty overrides mean "inherit from the route default".
    </p>
  </HelpModal>
{:else if activeHelp === 'section:mirror'}
  <HelpModal title="Shadow / Mirror" onclose={() => { activeHelp = null; }}>
    <p>
      Copy every matching request to alternate <em>shadow</em> backends
      in parallel with the primary call. Mirror responses are
      <strong>discarded</strong>; the client only ever sees the primary
      response.
    </p>
    <p>
      Shadow backends receive <code>X-Lorica-Mirror: 1</code> so they
      can filter this traffic out of their analytics, logs, and
      side-effects (no double-writes, no double-sends).
    </p>
    <p>
      Use cases:
    </p>
    <ul>
      <li>Test a new backend version against real production traffic
        without affecting users.</li>
      <li>Capture a replay corpus without impacting the primary path.</li>
      <li>Compare the old and new implementations' behaviour side-by-side.</li>
    </ul>
    <p>
      v1 mirrors method + URL + headers only, not the request body.
      Sampling is deterministic per <code>X-Request-Id</code>: the same
      logical request is either always mirrored or never mirrored.
    </p>
  </HelpModal>
{:else if activeHelp === 'backend_ids'}
  <HelpModal title="Backends" onclose={() => { activeHelp = null; }}>
    <p>
      Tick every backend this route may forward requests to. Backends are
      managed on the top-level <strong>Backends</strong> page.
    </p>
    <p>
      With 2 or more backends ticked, Lorica applies the configured Load
      Balancing algorithm on each request. Unhealthy backends are excluded
      automatically by the health-check engine.
    </p>
    <p>
      Setting 0 backends is valid only for routes that use
      <strong>Redirect to</strong> / <strong>Return status</strong>
      (configured in the General tab under Response override).
    </p>
  </HelpModal>
{:else if activeHelp === 'certificate_id'}
  <HelpModal title="TLS Certificate" onclose={() => { activeHelp = null; }}>
    <p>
      Certificate presented to clients connecting via HTTPS on port 443 for
      this hostname. Manage certificates on the top-level
      <strong>Certificates</strong> page (ACME auto-renew, manual upload, or
      self-signed).
    </p>
    <p>
      Leave "None (no TLS)" to serve HTTP-only. <strong>Force HTTPS</strong>
      toggle below requires a cert to be selected.
    </p>
  </HelpModal>
{:else if activeHelp === 'load_balancing'}
  <HelpModal title="Load Balancing" onclose={() => { activeHelp = null; }}>
    <p>Algorithm used to pick one backend per request:</p>
    <ul>
      <li>
        <strong>Weighted Round Robin</strong> (default) - rotates through
        backends respecting their weight. Simple, fair, predictable.
      </li>
      <li>
        <strong>Consistent Hash</strong> - hashes client IP (or a custom
        header) and maps to the same backend. Good when backends hold
        per-client state and sticky-cookie is not usable.
      </li>
      <li>
        <strong>Random</strong> - uniformly random pick. Useful under
        heavy load when state-of-art LB matters less than lock contention.
      </li>
      <li>
        <strong>Peak EWMA</strong> - picks the backend with the lowest
        exponentially-weighted moving average of response time. Adapts to
        backend latency drift.
      </li>
      <li>
        <strong>Least Connections</strong> - sends the next request to the
        backend with the fewest in-flight requests. Good for long-lived
        connections (WebSockets, streaming).
      </li>
    </ul>
    <p>
      Changing this on a live route with <strong>Sticky sessions</strong>
      on can break existing client affinity - most algorithms do not give
      the same backend for the same client.
    </p>
  </HelpModal>
{:else if activeHelp === 'force_https'}
  <HelpModal title="Force HTTPS redirect" onclose={() => { activeHelp = null; }}>
    <p>
      Requests arriving on port 80 (HTTP) receive a 301 redirect to the
      same URL on port 443 (HTTPS).
    </p>
    <p>
      Requires a TLS certificate to be selected - otherwise the redirect
      would point clients at an endpoint that cannot be reached.
    </p>
    <p>
      ACME HTTP-01 challenges are excluded from this redirect so
      certificate renewal continues to work.
    </p>
  </HelpModal>
{:else if activeHelp === 'sticky_session'}
  <HelpModal title="Sticky sessions" onclose={() => { activeHelp = null; }}>
    <p>
      Lorica sets a <code>LORICA_SRV</code> cookie on the first response
      identifying which backend served it. Subsequent requests from the
      same client return to the same backend.
    </p>
    <p>
      Useful when the application holds per-client state in memory (login
      sessions, shopping carts, WebSocket connections) and cannot share
      that state across backends.
    </p>
    <p>
      Falls back to regular load balancing when the cookie is absent or
      points at an unhealthy backend.
    </p>
    <p>
      <strong>Interaction with Traffic splits:</strong> a sticky cookie can
      pin a client to a backend outside the weight bucket they were
      originally assigned. Keep sticky sessions off when running a fair
      canary, or plan for some drift.
    </p>
  </HelpModal>
{/if}

<style>
  .tab-content { display: flex; flex-direction: column; gap: 1.25rem; }

  .warn-banner {
    margin-top: 0.5rem;
    padding: 0.5rem 0.75rem;
    background: rgba(245, 158, 11, 0.08);
    border-left: 3px solid var(--color-orange, #f59e0b);
    border-radius: 0 0.25rem 0.25rem 0;
    font-size: 0.8125rem;
    color: var(--color-text);
    line-height: 1.45;
  }
  .warn-banner strong { color: var(--color-text-heading); }

  .eval-order-banner {
    font-size: 0.8125rem;
    padding: 0.5rem 0.75rem;
    border-left: 3px solid var(--color-green, #10b981);
    background: rgba(16, 185, 129, 0.08);
    color: var(--color-text);
    border-radius: 0 0.25rem 0.25rem 0;
  }

  .eval-order-banner strong {
    color: var(--color-text-heading);
  }

  .eval-order-banner .step {
    display: inline-block;
    min-width: 1.125rem;
    padding: 0 0.25rem;
    margin: 0 0.0625rem;
    border-radius: 9999px;
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    font-size: 0.6875rem;
    font-weight: 700;
    color: var(--color-text-heading);
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

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

  /* Wraps an embedded tab component (Canary / HeaderRules /
     PathRules). The child paints its own tab-content wrapper with no
     outer padding, so we add breathing room around it on all sides -
     otherwise inline buttons like "Add rule" end up flush against
     the panel edge. */
  .subsection-body-panel {
    padding: 0.75rem 0.875rem 1rem;
  }

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

  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

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
