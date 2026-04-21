<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';
  import SubsectionHeader from '../SubsectionHeader.svelte';
  import FieldHelpButton from '../FieldHelpButton.svelte';
  import HelpModal from '../HelpModal.svelte';
  import { validateHttpMethodList } from '../../lib/validators';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  function numErr(raw: number | string, min: number, max: number, label: string): string | null {
    const str = String(raw).trim();
    if (str === '') return null;
    const n = Number(str);
    if (!Number.isInteger(n) || n < min || n > max) {
      return `${label} must be an integer in ${min}..${max}`;
    }
    return null;
  }
  let connectErr = $state<string | null>(null);
  let readErr = $state<string | null>(null);
  let sendErr = $state<string | null>(null);
  let retryAttemptsErr = $state<string | null>(null);
  let retryMethodsErr = $state<string | null>(null);
  function checkConnect() { connectErr = numErr(form.connect_timeout_s, 1, 3600, 'value'); }
  function checkRead() { readErr = numErr(form.read_timeout_s, 1, 3600, 'value'); }
  function checkSend() { sendErr = numErr(form.send_timeout_s, 1, 3600, 'value'); }
  function checkRetryAttempts() { retryAttemptsErr = numErr(form.retry_attempts, 0, 10, 'value'); }
  function checkRetryMethods() { retryMethodsErr = validateHttpMethodList(form.retry_on_methods); }

  let activeHelp = $state<
    | null
    | 'section:timeouts'
    | 'section:retry'
    | 'connect_timeout_s'
    | 'read_timeout_s'
    | 'send_timeout_s'
    | 'retry_attempts'
    | 'retry_on_methods'
  >(null);

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">

  <!-- ============ Timeouts ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Timeouts"
      description="How long Lorica waits for the backend at each stage of the upstream call."
      accent="blue"
      onhelp={() => { activeHelp = 'section:timeouts'; }}
    />
    <div class="subsection-body">
      <div class="form-row form-row-3">
        <div class="form-group" class:modified={isModified('connect_timeout_s')}>
          <label for="connect-timeout">
            Connect (s)
            <FieldHelpButton fieldLabel="Connect timeout" onhelp={() => { activeHelp = 'connect_timeout_s'; }} />
          </label>
          {#if isImported('connect_timeout_s')}<span class="imported-badge">imported</span>{/if}
          <input id="connect-timeout" type="number" min="1" max="3600" bind:value={form.connect_timeout_s} onblur={checkConnect} oninput={checkConnect} />
          {#if connectErr}<span class="field-error" role="alert">{connectErr}</span>{/if}
          <span class="hint">Max time to establish the TCP / TLS connection to a backend.</span>
        </div>
        <div class="form-group" class:modified={isModified('read_timeout_s')}>
          <label for="read-timeout">
            Read (s)
            <FieldHelpButton fieldLabel="Read timeout" onhelp={() => { activeHelp = 'read_timeout_s'; }} />
          </label>
          {#if isImported('read_timeout_s')}<span class="imported-badge">imported</span>{/if}
          <input id="read-timeout" type="number" min="1" max="3600" bind:value={form.read_timeout_s} onblur={checkRead} oninput={checkRead} />
          {#if readErr}<span class="field-error" role="alert">{readErr}</span>{/if}
          <span class="hint">Max time between bytes received from the backend.</span>
        </div>
        <div class="form-group" class:modified={isModified('send_timeout_s')}>
          <label for="send-timeout">
            Send (s)
            <FieldHelpButton fieldLabel="Send timeout" onhelp={() => { activeHelp = 'send_timeout_s'; }} />
          </label>
          {#if isImported('send_timeout_s')}<span class="imported-badge">imported</span>{/if}
          <input id="send-timeout" type="number" min="1" max="3600" bind:value={form.send_timeout_s} onblur={checkSend} oninput={checkSend} />
          {#if sendErr}<span class="field-error" role="alert">{sendErr}</span>{/if}
          <span class="hint">Max time between bytes sent to the backend.</span>
        </div>
      </div>
    </div>
  </section>

  <!-- ============ Retry ============ -->
  <section class="subsection">
    <SubsectionHeader
      title="Retry"
      description="Retry the upstream call when it fails. Applies only to idempotent methods by default."
      accent="amber"
      onhelp={() => { activeHelp = 'section:retry'; }}
    />
    <div class="subsection-body">
      <div class="form-row">
        <div class="form-group" class:modified={isModified('retry_attempts')}>
          <label for="retry-attempts">
            Retry attempts
            <FieldHelpButton fieldLabel="Retry attempts" onhelp={() => { activeHelp = 'retry_attempts'; }} />
          </label>
          {#if isImported('retry_attempts')}<span class="imported-badge">imported</span>{/if}
          <input id="retry-attempts" type="number" min="0" max="10" bind:value={form.retry_attempts} placeholder="No retry" onblur={checkRetryAttempts} oninput={checkRetryAttempts} />
          {#if retryAttemptsErr}<span class="field-error" role="alert">{retryAttemptsErr}</span>{/if}
          <span class="hint">Extra attempts on 5xx / connection errors. 0 = never retry.</span>
        </div>
        <div class="form-group" class:modified={isModified('retry_on_methods')}>
          <label for="retry-methods">
            Retry on methods
            <FieldHelpButton fieldLabel="Retry on methods" onhelp={() => { activeHelp = 'retry_on_methods'; }} />
          </label>
          <input id="retry-methods" type="text" bind:value={form.retry_on_methods} placeholder="GET, HEAD, OPTIONS" onblur={checkRetryMethods} oninput={checkRetryMethods} />
          {#if retryMethodsErr}<span class="field-error" role="alert">{retryMethodsErr}</span>{/if}
          <span class="hint">Comma-separated. Leave empty for all methods.</span>
        </div>
      </div>
    </div>
  </section>
</div>

{#if activeHelp === 'section:timeouts'}
  <HelpModal title="Timeouts" onclose={() => { activeHelp = null; }}>
    <p>
      Three independent timeouts gate how long Lorica waits for a
      backend before giving up and returning 504 Gateway Timeout.
    </p>
    <ul>
      <li><strong>Connect</strong> - TCP + TLS handshake to reach the
        backend in the first place. Low single-digit seconds is typical.</li>
      <li><strong>Read</strong> - Gap between bytes received from the
        backend while streaming the response. Should cover your
        backend's 99th-percentile service time.</li>
      <li><strong>Send</strong> - Gap between bytes sent to the
        backend for large uploads. Lift this for routes handling
        file uploads.</li>
    </ul>
    <p>
      Per-route tuning matters: a slow internal API may legitimately
      need 60 s read timeout, while a fast health endpoint should stay
      at 5 s so failures fail fast.
    </p>
  </HelpModal>
{:else if activeHelp === 'section:retry'}
  <HelpModal title="Retry" onclose={() => { activeHelp = null; }}>
    <p>
      When the backend returns a 5xx or the connection fails, Lorica
      can retry the call against the same or another backend up to
      <code>Retry attempts</code> additional times.
    </p>
    <p>
      <strong>Idempotent methods only</strong>. Retrying a non-idempotent
      method (POST, PATCH) may cause the server to process the same
      operation twice. The <code>Retry on methods</code> field gates
      this - default is GET + HEAD + OPTIONS when empty, all methods
      when explicitly listed.
    </p>
    <p>
      Lorica picks a different healthy backend on each retry when
      multiple are configured in the Routing tab.
    </p>
  </HelpModal>
{:else if activeHelp === 'connect_timeout_s'}
  <HelpModal title="Connect timeout" onclose={() => { activeHelp = null; }}>
    <p>
      Max duration for the TCP (and TLS if applicable) handshake to a
      backend. If the backend does not accept the connection within
      this window, Lorica moves on to the next backend or returns 504.
    </p>
    <p>
      Equivalent: <code>proxy_connect_timeout</code> (Nginx), <code>timeout
      connect</code> (HAProxy), <code>dialTimeout</code> (Traefik).
    </p>
    <p>
      Typical value: 5 s. Lower it (2 s) when your backends are
      always on the same network segment and any slow connect means
      the backend is unhealthy.
    </p>
  </HelpModal>
{:else if activeHelp === 'read_timeout_s'}
  <HelpModal title="Read timeout" onclose={() => { activeHelp = null; }}>
    <p>
      Max time between two consecutive bytes Lorica reads from the
      backend during the response stream. A slow response that trickles
      within this window is fine; a stalled response times out.
    </p>
    <p>
      Equivalent: <code>proxy_read_timeout</code> (Nginx), <code>timeout
      server</code> (HAProxy), <code>responseHeaderTimeout</code>
      (Traefik).
    </p>
    <p>
      Raise this for routes serving long-polling, server-sent events,
      or slow database-backed endpoints. Keep it low (5-10 s) for
      endpoints with sub-second SLO.
    </p>
  </HelpModal>
{:else if activeHelp === 'send_timeout_s'}
  <HelpModal title="Send timeout" onclose={() => { activeHelp = null; }}>
    <p>
      Max time between two consecutive bytes Lorica writes to the
      backend while forwarding the request body. Stalled uploads time
      out and return 504.
    </p>
    <p>
      Equivalent: <code>proxy_send_timeout</code> (Nginx).
    </p>
    <p>
      Raise this for routes that handle large file uploads over slow
      client connections. Default is fine for most routes.
    </p>
  </HelpModal>
{:else if activeHelp === 'retry_attempts'}
  <HelpModal title="Retry attempts" onclose={() => { activeHelp = null; }}>
    <p>
      Number of <strong>additional</strong> attempts after the initial
      request fails. <code>retry_attempts = 2</code> means up to 3
      total attempts (1 original + 2 retries).
    </p>
    <p>
      Retried conditions:
    </p>
    <ul>
      <li>Connect / Send / Read timeout.</li>
      <li>TCP connection reset by the backend.</li>
      <li>5xx response codes (500, 502, 503, 504).</li>
    </ul>
    <p>
      Lorica picks a different healthy backend on each retry when the
      route has multiple backends configured. Only retries methods
      listed in <code>Retry on methods</code>.
    </p>
    <p>
      Set to 0 to disable entirely. Rarely useful above 2 - beyond
      that, failures tend to be persistent.
    </p>
  </HelpModal>
{:else if activeHelp === 'retry_on_methods'}
  <HelpModal title="Retry on methods" onclose={() => { activeHelp = null; }}>
    <p>
      Comma-separated HTTP methods that may be retried. Prevents
      accidentally retrying a non-idempotent call (POST, PATCH) which
      could cause the server to process the same request twice.
    </p>
    <p>
      Typical values:
    </p>
    <ul>
      <li><em>(empty)</em> - default list: GET, HEAD, OPTIONS.</li>
      <li><code>GET, HEAD, PUT, DELETE</code> - adding PUT/DELETE is
        safe if your API is truly idempotent.</li>
      <li><code>GET, HEAD, OPTIONS, POST</code> - only if you are sure
        your POSTs are idempotent (with an <code>Idempotency-Key</code>
        header, for example).</li>
    </ul>
    <p>
      If <code>Retry attempts</code> is 0, this field is ignored.
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

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .form-row-3 { grid-template-columns: 1fr 1fr 1fr; }

  .hint { display: block; font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; margin-top: 0.25rem; }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }

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
