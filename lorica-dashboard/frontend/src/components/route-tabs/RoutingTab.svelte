<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import type { BackendResponse, CertificateResponse } from '../../lib/api';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import StatusBadge from '../StatusBadge.svelte';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';

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
</script>

<div class="tab-content">
  <!-- ============ Default backends ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Default backends"
      description="The primary backend pool, TLS termination, and how requests are distributed when no header/path/canary rule matches."
      accent="routing"
      onhelp={() => { activeHelp = 'section:default_backends'; }}
    />
    <div class="subsection-body">

      <div class="form-group">
        <label>
          <span>Backends</span>
          <FieldHelpButton fieldLabel="Backends" onhelp={() => { activeHelp = 'backend_ids'; }} />
        </label>
        {#if isImported('backend_ids')}<span class="imported-badge">imported</span>{/if}
        {#if backends.length === 0}
          <p class="text-muted small">No backends available - create one first in the Backends page.</p>
        {:else}
          <div class="checkbox-list">
            {#each backends as b (b.id)}
              <label class="checkbox-item">
                <input type="checkbox" checked={form.backend_ids.includes(b.id)} onchange={() => toggleBackend(b.id)} />
                <span>{b.name ? `${b.name} (${b.address})` : b.address}</span>
                <StatusBadge status={b.health_status === 'healthy' ? 'healthy' : b.health_status === 'degraded' ? 'degraded' : b.health_status === 'down' ? 'down' : 'unknown'} />
              </label>
            {/each}
          </div>
        {/if}
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
        <span class="hint">Returns a client to the same backend via a LORICA_SRV cookie. Useful for stateful apps.</span>
      </div>

    </div>
  </section>

  <!-- ============ Placeholder: upcoming subsections ============ -->
  <section class="upcoming">
    <p class="upcoming-title">Coming in the next v1.4.0 refactor passes:</p>
    <ul>
      <li><strong>Traffic splits</strong> - weighted canary distribution (currently in the Canary tab).</li>
      <li><strong>Header-based routes</strong> - route by request header to alternate backends (currently in the Header Rules tab).</li>
      <li><strong>Path-based routes</strong> - per-path backend / cache / status overrides (currently in the Path Rules tab).</li>
      <li><strong>Shadow / Mirror</strong> - copy traffic to a debug backend for testing (currently in the Security tab).</li>
    </ul>
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
      on can break existing client affinity - most algorithms don't give
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

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    max-height: 150px;
    overflow-y: auto;
    padding: 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.8125rem; }
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

  .upcoming {
    background: var(--color-bg-input);
    border: 1px dashed var(--color-border);
    border-radius: 0.5rem;
    padding: 1rem;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
  }

  .upcoming-title {
    font-weight: 600;
    margin: 0 0 0.5rem;
    color: var(--color-text);
  }

  .upcoming ul {
    margin: 0;
    padding-left: 1.25rem;
  }

  .upcoming li {
    margin-bottom: 0.25rem;
  }
</style>
