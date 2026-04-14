<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';

  import { api, type SecurityHeaderPreset, type BackendResponse } from '../../lib/api';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
    customPresets?: SecurityHeaderPreset[];
    backends?: BackendResponse[];
    /**
     * The `mtls.ca_cert_pem` value loaded from the server for this
     * route, or an empty string when creating or when mTLS is off.
     * Used to surface a "requires restart" hint when the operator
     * edits the CA bundle at runtime - rustls ServerConfig is
     * immutable after the listener is built.
     */
    initialMtlsCaCertPem?: string;
  }

  let {
    form = $bindable(),
    importedFields,
    customPresets = [],
    backends = [],
    initialMtlsCaCertPem = '',
  }: Props = $props();

  // True only when the operator is editing an already-configured
  // mtls route and changed the CA PEM bytes. Required + org
  // allowlist edits hot-reload, so they don't trigger this hint.
  let mtlsCaChangedFromInitial = $derived(
    initialMtlsCaCertPem.trim() !== '' &&
      form.mtls_ca_cert_pem.trim() !== initialMtlsCaCertPem.trim(),
  );

  function toggleMirrorBackend(id: string) {
    if (form.mirror_backend_ids.includes(id)) {
      form.mirror_backend_ids = form.mirror_backend_ids.filter((b) => b !== id);
    } else {
      form.mirror_backend_ids = [...form.mirror_backend_ids, id];
    }
  }

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  // F-14 test/validate actions. Each action holds a small state
  // machine: idle -> running -> result (ok | error). The result is
  // displayed inline under the relevant field so the operator can
  // see the outcome without leaving the drawer.
  type ActionState =
    | { status: 'idle' }
    | { status: 'running' }
    | { status: 'ok'; summary: string }
    | { status: 'error'; message: string };

  let mtlsValidation: ActionState = $state({ status: 'idle' });
  let faTest: ActionState = $state({ status: 'idle' });

  async function runMtlsValidate() {
    const pem = form.mtls_ca_cert_pem.trim();
    if (pem === '') {
      mtlsValidation = { status: 'error', message: 'Paste a PEM bundle first.' };
      return;
    }
    mtlsValidation = { status: 'running' };
    const res = await api.validateMtlsPem(pem);
    if (res.error) {
      mtlsValidation = { status: 'error', message: res.error.message };
    } else if (res.data) {
      const n = res.data.ca_count;
      const subj = res.data.subjects.slice(0, 5).join(' · ');
      const more = res.data.subjects.length > 5 ? ` (+${res.data.subjects.length - 5} more)` : '';
      mtlsValidation = {
        status: 'ok',
        summary: `${n} CA cert${n === 1 ? '' : 's'} parsed: ${subj}${more}`,
      };
    }
  }

  async function runForwardAuthTest() {
    const addr = form.forward_auth_address.trim();
    if (addr === '') {
      faTest = { status: 'error', message: 'Set the auth service URL first.' };
      return;
    }
    faTest = { status: 'running' };
    const res = await api.validateForwardAuth(addr, form.forward_auth_timeout_ms);
    if (res.error) {
      faTest = { status: 'error', message: res.error.message };
    } else if (res.data) {
      const hdrSummary = Object.entries(res.data.headers)
        .map(([k, v]) => `${k}: ${v.length > 40 ? v.slice(0, 40) + '…' : v}`)
        .join(' · ');
      faTest = {
        status: 'ok',
        summary: `${res.data.status} in ${res.data.elapsed_ms} ms${hdrSummary ? ` — ${hdrSummary}` : ''}`,
      };
    }
  }
</script>

<div class="tab-content security-tab-content">
  <!-- In-tab table of contents: the Security tab hosts 6 unrelated
       feature families. Anchor jumps let users go directly to the
       one they want to configure without scrolling the full form. -->
  <nav class="tab-toc" aria-label="Security subsections">
    <a href="#sec-headers">Headers &amp; limits</a>
    <a href="#sec-ip-lists">IP lists</a>
    <a href="#sec-basic-auth">Basic auth</a>
    <a href="#sec-forward-auth">Forward auth</a>
    <a href="#sec-mirror">Mirroring</a>
    <a href="#sec-mtls">mTLS</a>
  </nav>

  <section id="sec-headers" class="subsection-anchor">
  <div class="form-group" class:modified={isModified('security_headers')}>
    <label for="security-headers">Security headers preset</label>
    {#if isImported('security_headers')}<span class="imported-badge">imported</span>{/if}
    <select id="security-headers" bind:value={form.security_headers}>
      <option value="strict">Strict</option>
      <option value="moderate">Moderate</option>
      <option value="none">None</option>
      {#each customPresets as preset (preset.name)}
        <option value={preset.name}>{preset.name} (custom)</option>
      {/each}
    </select>
    <span class="hint">Nginx: add_header Strict-Transport-Security... | Traefik: Headers middleware</span>
  </div>

  <div class="form-row form-row-3">
    <div class="form-group" class:modified={isModified('max_body_mb')}>
      <label for="max-body">Max body (MB)</label>
      {#if isImported('max_body_mb')}<span class="imported-badge">imported</span>{/if}
      <input id="max-body" type="number" min="0" step="1" bind:value={form.max_body_mb} placeholder="No limit" />
      <span class="hint">Nginx: client_max_body_size | Traefik: Buffering maxRequestBodyBytes</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_rps')}>
      <label for="rate-rps">Rate limit RPS</label>
      {#if isImported('rate_limit_rps')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-rps" type="number" min="1" bind:value={form.rate_limit_rps} placeholder="No limit" />
      <span class="hint">Nginx: limit_req zone rate=Xr/s | Traefik: RateLimit middleware</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_burst')}>
      <label for="rate-burst">Rate limit burst</label>
      {#if isImported('rate_limit_burst')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-burst" type="number" min="1" bind:value={form.rate_limit_burst} placeholder="No limit" />
    </div>
  </div>
  </section>

  <section id="sec-ip-lists" class="subsection-anchor">
  <div class="form-row">
    <div class="form-group" class:modified={isModified('ip_allowlist')}>
      <label for="ip-allow">IP allowlist <span class="hint">(one per line)</span></label>
      {#if isImported('ip_allowlist')}<span class="imported-badge">imported</span>{/if}
      <textarea id="ip-allow" rows="3" bind:value={form.ip_allowlist} placeholder="192.168.1.0/24&#10;10.0.0.1"></textarea>
    </div>
    <div class="form-group" class:modified={isModified('ip_denylist')}>
      <label for="ip-deny">IP denylist <span class="hint">(one per line)</span></label>
      {#if isImported('ip_denylist')}<span class="imported-badge">imported</span>{/if}
      <textarea id="ip-deny" rows="3" bind:value={form.ip_denylist} placeholder="203.0.113.0/24"></textarea>
    </div>
  </div>
  </section>

  <section id="sec-basic-auth" class="subsection-anchor">
  <div class="form-row">
    <div class="form-group" class:modified={isModified('basic_auth_username')}>
      <label for="basic-auth-user">Basic auth username</label>
      <input id="basic-auth-user" type="text" bind:value={form.basic_auth_username} placeholder="Leave empty to disable" />
      <span class="hint">HTTP Basic Auth for staging or internal tools. Nginx: auth_basic | Traefik: BasicAuth middleware</span>
    </div>
    <div class="form-group" class:modified={isModified('basic_auth_password')}>
      <label for="basic-auth-pass">Basic auth password</label>
      <input id="basic-auth-pass" type="password" bind:value={form.basic_auth_password} placeholder={form.basic_auth_username ? '(unchanged)' : 'Leave empty to disable'} />
      <span class="hint">Password is hashed (Argon2id) before storage. Send a new value to change it.</span>
    </div>
  </div>

  </section>

  <section id="sec-forward-auth" class="subsection-anchor">
  <h3 class="subsection-title">Forward authentication</h3>
  <p class="subsection-hint">
    Before proxying to the upstream, issue a GET sub-request to an external
    auth service (Authelia, Authentik, Keycloak, oauth2-proxy). 2xx = allow,
    401/403/3xx = forwarded verbatim to the client (so Authelia's login
    redirect works), other = fail closed 503.
  </p>

  <div class="form-group" class:modified={form.forward_auth_address !== ''}>
    <label for="fa-address">Auth service URL</label>
    <input
      id="fa-address"
      type="text"
      bind:value={form.forward_auth_address}
      placeholder="http://authelia.internal:9091/api/verify"
    />
    <span class="hint">Empty = feature disabled. Must be an absolute http(s):// URL.</span>
    <div class="inline-action">
      <button
        type="button"
        class="btn-inline-action"
        onclick={runForwardAuthTest}
        disabled={form.forward_auth_address.trim() === '' || faTest.status === 'running'}
      >
        {faTest.status === 'running' ? 'Testing…' : 'Test connection'}
      </button>
      {#if faTest.status === 'ok'}
        <span class="action-result ok">OK · {faTest.summary}</span>
      {:else if faTest.status === 'error'}
        <span class="action-result err">{faTest.message}</span>
      {/if}
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={form.forward_auth_timeout_ms !== 5000}>
      <label for="fa-timeout">Timeout (ms)</label>
      <input
        id="fa-timeout"
        type="number"
        min="1"
        max="60000"
        bind:value={form.forward_auth_timeout_ms}
        disabled={!form.forward_auth_address}
        title={!form.forward_auth_address ? 'Set an auth service URL above to enable this option' : ''}
      />
      <span class="hint">Per-request total timeout. 1..60000 ms. Default 5000.</span>
    </div>
    <div class="form-group" class:modified={form.forward_auth_response_headers !== ''}>
      <label for="fa-response-headers">Response headers to inject</label>
      <input
        id="fa-response-headers"
        type="text"
        bind:value={form.forward_auth_response_headers}
        placeholder="Remote-User, Remote-Groups, Remote-Email"
        disabled={!form.forward_auth_address}
        title={!form.forward_auth_address ? 'Set an auth service URL above to enable this option' : ''}
      />
      <span class="hint">Comma or newline-separated; copied from the auth response into the upstream request on 2xx only.</span>
    </div>
  </div>

  </section>

  <section id="sec-mirror" class="subsection-anchor">
  <h3 class="subsection-title">Request mirroring (shadow testing)</h3>
  <p class="subsection-hint">
    Fire-and-forget shadow copies of every request to alternate backends.
    Mirror responses are discarded. Shadow backends receive
    <code>X-Lorica-Mirror: 1</code> so they can filter this traffic out of
    their normal analytics. v1 mirrors headers + method + URL only, not
    the request body.
  </p>

  <div class="form-group" class:modified={form.mirror_backend_ids.length > 0}>
    <label id="mirror-backends-label" for="mirror-backend-{backends[0]?.id ?? 'none'}">Shadow backends</label>
    {#if backends.length === 0}
      <p class="text-muted small">No backends available.</p>
    {:else}
      <div class="checkbox-list" role="group" aria-labelledby="mirror-backends-label">
        {#each backends as b (b.id)}
          <label class="checkbox-item">
            <input id="mirror-backend-{b.id}" type="checkbox" checked={form.mirror_backend_ids.includes(b.id)} onchange={() => toggleMirrorBackend(b.id)} />
            <span>{b.name ? `${b.name} (${b.address})` : b.address}</span>
          </label>
        {/each}
      </div>
    {/if}
    <span class="hint">Leave empty to disable mirroring.</span>
    {#if form.mirror_backend_ids.length > 0}
      <div class="mirror-summary" aria-live="polite">
        <strong>{form.mirror_backend_ids.length}</strong> shadow backend{form.mirror_backend_ids.length === 1 ? '' : 's'}
        <span class="sep" aria-hidden="true">·</span>
        sampling <strong>{form.mirror_sample_percent}%</strong>
        <span class="sep" aria-hidden="true">·</span>
        {form.mirror_max_body_bytes === 0
          ? 'headers-only'
          : `max body ${(form.mirror_max_body_bytes / 1048576).toFixed(form.mirror_max_body_bytes >= 1048576 ? 0 : 2)} MiB`}
        <span class="sep" aria-hidden="true">·</span>
        {form.mirror_backend_ids.length * form.mirror_sample_percent / 100} mirror request{(form.mirror_backend_ids.length * form.mirror_sample_percent / 100) === 1 ? '' : 's'} per primary (avg)
      </div>
    {/if}
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={form.mirror_sample_percent !== 100}>
      <label for="mirror-sample">Sample percent</label>
      <input
        id="mirror-sample"
        type="number"
        min="0"
        max="100"
        bind:value={form.mirror_sample_percent}
        disabled={form.mirror_backend_ids.length === 0}
        title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
      />
      <span class="hint">0..100. Sticky per X-Request-Id so retries of the same request stay in or out.</span>
    </div>
    <div class="form-group" class:modified={form.mirror_timeout_ms !== 5000}>
      <label for="mirror-timeout">Timeout (ms)</label>
      <input
        id="mirror-timeout"
        type="number"
        min="1"
        max="60000"
        bind:value={form.mirror_timeout_ms}
        disabled={form.mirror_backend_ids.length === 0}
        title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
      />
      <span class="hint">Slow mirrors are dropped silently; never impacts the primary request.</span>
    </div>
  </div>

  <div class="form-group" class:modified={form.mirror_max_body_bytes !== 1048576}>
    <label for="mirror-max-body">Max body bytes</label>
    <input
      id="mirror-max-body"
      type="number"
      min="0"
      max="134217728"
      bind:value={form.mirror_max_body_bytes}
      disabled={form.mirror_backend_ids.length === 0}
        title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
    />
    <span class="hint">
      Max body size buffered for mirror sub-requests. Requests with a body
      larger than this are sent to the primary normally but NOT mirrored
      (a truncated body would mislead the shadow). Default 1 MiB
      (1048576). Set to 0 for headers-only mirroring. Max 128 MiB.
    </span>
  </div>

  </section>

  <section id="sec-mtls" class="subsection-anchor">
  <h3 class="subsection-title">mTLS client verification</h3>
  <p class="subsection-hint">
    Require connecting clients to present an X.509 certificate signed by
    the configured CA bundle. Chain validation happens at the TLS
    handshake; this route gates the request with
    <code>required</code> (no-cert &rarr; 496) and an optional
    organization allowlist (non-matching O= &rarr; 495). Changes to the
    CA PEM need a restart; toggling <code>required</code> or editing the
    allowlist hot-reloads.
  </p>

  <div class="form-group" class:modified={form.mtls_ca_cert_pem !== ''}>
    <label for="mtls-ca">Client CA bundle (PEM)</label>
    <textarea
      id="mtls-ca"
      rows="6"
      bind:value={form.mtls_ca_cert_pem}
      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
    ></textarea>
    <span class="hint">
      One or more <code>-----BEGIN CERTIFICATE-----</code> blocks. Empty = feature
      disabled. Max 1 MiB.
    </span>
    <div class="inline-action">
      <button
        type="button"
        class="btn-inline-action"
        onclick={runMtlsValidate}
        disabled={form.mtls_ca_cert_pem.trim() === '' || mtlsValidation.status === 'running'}
      >
        {mtlsValidation.status === 'running' ? 'Validating…' : 'Validate PEM'}
      </button>
      {#if mtlsValidation.status === 'ok'}
        <span class="action-result ok">{mtlsValidation.summary}</span>
      {:else if mtlsValidation.status === 'error'}
        <span class="action-result err">{mtlsValidation.message}</span>
      {/if}
    </div>
    {#if mtlsCaChangedFromInitial}
      <div class="warn-banner" role="status" aria-live="polite">
        <strong>Restart required.</strong> The TLS listener's client-CA
        bundle is fixed after startup (rustls
        <code>ServerConfig</code> is immutable). Saving will persist
        the new bundle, but the change won't take effect on
        handshakes until Lorica is restarted.
        <ul class="restart-hints">
          <li>systemd: <code>sudo systemctl restart lorica</code></li>
          <li>Docker: <code>docker restart &lt;container&gt;</code></li>
          <li>Kubernetes: <code>kubectl rollout restart deployment/lorica</code></li>
          <li>Foreground process: stop with Ctrl+C and relaunch</li>
        </ul>
        Toggling <em>Required</em> and editing <em>Allowed
        organizations</em> hot-reload normally without a restart.
      </div>
    {/if}
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={form.mtls_required}>
      <label class="checkbox-item" for="mtls-required">
        <input
          id="mtls-required"
          type="checkbox"
          bind:checked={form.mtls_required}
          disabled={form.mtls_ca_cert_pem.trim() === ''}
          title={form.mtls_ca_cert_pem.trim() === '' ? 'Paste a client CA bundle above to enable this option' : ''}
        />
        <span>Required (reject if no client cert)</span>
      </label>
      <span class="hint">
        On &rarr; no cert presented returns 496. Off &rarr; opportunistic
        (no cert passes through; a presented cert must still pass the
        allowlist if one is configured).
      </span>
    </div>
    <div class="form-group" class:modified={form.mtls_allowed_organizations !== ''}>
      <label for="mtls-orgs">Allowed organizations</label>
      <input
        id="mtls-orgs"
        type="text"
        bind:value={form.mtls_allowed_organizations}
        placeholder="Acme Corp, Beta Inc"
        disabled={form.mtls_ca_cert_pem.trim() === ''}
        title={form.mtls_ca_cert_pem.trim() === '' ? 'Paste a client CA bundle above to enable this option' : ''}
      />
      <span class="hint">
        Comma or newline-separated exact matches against the cert
        subject's <code>O=</code> field. Empty = accept any cert that
        chains to the bundle.
      </span>
    </div>
  </div>
  </section>
</div>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }

  /* In-tab table of contents. Sticks near the top of the scroll
     container so operators can jump to any subsection without
     losing context. Scrolls horizontally on narrow screens rather
     than wrapping to two rows - keeps the tab body's vertical
     space predictable. */
  .tab-toc {
    display: flex;
    flex-wrap: wrap;
    gap: 0.375rem;
    padding: 0.5rem 0 0.75rem;
    margin-bottom: 0.5rem;
    border-bottom: 1px solid var(--color-border-subtle, var(--color-border));
    position: sticky;
    top: 0;
    background: var(--color-bg, #fff);
    z-index: 1;
  }
  .tab-toc a {
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    text-decoration: none;
    border: 1px solid transparent;
  }
  .tab-toc a:hover {
    background: rgba(59, 130, 246, 0.08);
    color: var(--color-primary);
    border-color: rgba(59, 130, 246, 0.25);
  }
  .subsection-anchor {
    /* Offset anchor target by the sticky TOC height + header
       padding so the anchored h3 isn't hidden under the rail. */
    scroll-margin-top: 4rem;
  }

  .form-group { margin-bottom: 1rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .subsection-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--color-text);
    margin: 1.25rem 0 0.25rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--color-border);
  }
  .subsection-hint {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin: 0 0 0.75rem;
    line-height: 1.4;
  }
  /* Disabled inputs: explicit token colors rather than opacity so
     the resulting text still meets WCAG 4.5:1 on both light and
     dark themes. Opacity:0.5 on already-muted text falls below AA. */
  .form-group input:disabled,
  .form-group textarea:disabled {
    background: var(--color-bg-disabled, rgba(127, 127, 127, 0.08));
    color: var(--color-text-muted);
    cursor: not-allowed;
    border-color: var(--color-border);
  }
  /* Keep the checkbox-item label muted but not invisible when the
     parent feature is off; the label text is still readable. */
  .form-group input[type="checkbox"]:disabled + span { color: var(--color-text-muted); }

  .checkbox-list { display: flex; flex-direction: column; gap: 0.25rem; max-height: 10rem; overflow-y: auto; }
  .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; cursor: pointer; padding: 0.25rem 0; }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }
  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.75rem; }
  code { font-family: ui-monospace, monospace; font-size: 0.75rem; background: var(--color-bg-input); padding: 0.05rem 0.25rem; border-radius: 0.25rem; }

  .form-group select,
  .form-group input[type="number"],
  .form-group input[type="text"],
  .form-group input[type="password"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group select:focus,
  .form-group input:focus { outline: none; border-color: var(--color-primary); }

  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: var(--mono);
    resize: vertical;
  }

  .form-group textarea:focus { outline: none; border-color: var(--color-primary); }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .form-row-3 { grid-template-columns: 1fr 1fr 1fr; }

  .hint { font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; }

  .mirror-summary {
    margin-top: 0.5rem;
    padding: 0.5rem 0.75rem;
    background: rgba(59, 130, 246, 0.08);
    border: 1px solid rgba(59, 130, 246, 0.25);
    border-radius: 4px;
    font-size: 0.75rem;
    color: var(--color-text);
  }
  .mirror-summary strong { color: var(--color-primary); }
  .mirror-summary .sep { margin: 0 0.375rem; opacity: 0.5; }

  /* Inline action row: small button + trailing result badge, used
     by the Test connection / Validate PEM affordances. Kept low-key
     visually so it doesn't compete with primary form controls. */
  .inline-action { margin-top: 0.375rem; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
  .btn-inline-action {
    padding: 0.25rem 0.625rem;
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--color-primary);
    background: transparent;
    border: 1px solid var(--color-primary);
    border-radius: 0.25rem;
    cursor: pointer;
  }
  .btn-inline-action:hover:not(:disabled) { background: rgba(59, 130, 246, 0.08); }
  .btn-inline-action:disabled { opacity: 0.5; cursor: not-allowed; }
  .action-result {
    font-size: 0.75rem;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
  }
  .action-result.ok {
    background: rgba(22, 163, 74, 0.12);
    color: #16a34a;
    border: 1px solid rgba(22, 163, 74, 0.3);
  }
  .action-result.err {
    background: rgba(220, 38, 38, 0.12);
    color: #dc2626;
    border: 1px solid rgba(220, 38, 38, 0.3);
  }

  .warn-banner {
    margin-top: 0.5rem;
    padding: 0.5rem 0.75rem;
    border: 1px solid rgba(234, 179, 8, 0.4);
    background: rgba(234, 179, 8, 0.08);
    border-radius: 4px;
    font-size: 0.75rem;
    line-height: 1.4;
    color: var(--color-text);
  }
  .warn-banner code { background: rgba(0,0,0,0.08); padding: 0 0.25rem; border-radius: 2px; }
  .restart-hints { margin: 0.5rem 0; padding-left: 1.25rem; list-style: disc; }
  .restart-hints li { margin: 0.125rem 0; }

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
