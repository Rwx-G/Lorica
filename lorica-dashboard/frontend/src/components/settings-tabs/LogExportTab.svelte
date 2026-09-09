<script lang="ts">
  import { api } from '../../lib/api';
  import { validateHostPort, validateExtraSd } from '../../lib/validators';
  import { isSuperAdmin } from '../../lib/auth';

  interface LogExportFormShape {
    syslog_endpoint: string;
    syslog_transport: string;
    syslog_facility: number;
    syslog_severity_access: number;
    syslog_severity_waf: number;
    syslog_severity_audit: number;
    syslog_access_enabled: boolean;
    syslog_waf_enabled: boolean;
    syslog_audit_enabled: boolean;
    syslog_tls_ca_pem: string;
    syslog_tls_client_cert_pem: string;
    syslog_tls_client_key_pem: string;
    syslog_extra_sd: string;
    otlp_logs_enabled: boolean;
    otlp_logs_auth_header: string;
  }

  interface Props {
    settingsForm: LogExportFormShape;
    expanded: boolean;
    toggleSection: () => void;
    onSave: () => void | Promise<void>;
    settingsSaving: boolean;
    settingsMsg: string;
    settingsError: string;
  }

  let {
    settingsForm = $bindable(),
    expanded,
    toggleSection,
    onSave,
    settingsSaving,
    settingsMsg,
    settingsError,
  }: Props = $props();

  // --- Blur-time field validators ---
  let endpointError = $state<string | null>(null);
  let extraSdError = $state<string | null>(null);
  function checkEndpoint() {
    endpointError = validateHostPort(settingsForm.syslog_endpoint);
  }
  function checkExtraSd() {
    extraSdError = validateExtraSd(settingsForm.syslog_extra_sd);
  }

  // --- Test connection state: one state machine per sink, one
  // shared runner (the two handlers used to be ~30 duplicated lines
  // each; a third sink would have tripled the pattern).
  interface SinkTestState {
    testing: boolean;
    msg: string;
    ok: boolean;
  }
  let syslogTest = $state<SinkTestState>({ testing: false, msg: '', ok: false });
  let otlpTest = $state<SinkTestState>({ testing: false, msg: '', ok: false });

  async function runSinkTest(
    target: SinkTestState,
    call: () => ReturnType<typeof api.testSyslog>,
    unreachableMsg: string
  ): Promise<void> {
    target.testing = true;
    target.msg = '';
    target.ok = false;
    try {
      const res = await call();
      if (res.error) {
        target.ok = false;
        target.msg = res.error.message || 'Test connection failed (unknown error)';
      } else if (res.data) {
        target.ok = res.data.ok;
        target.msg = res.data.ok
          ? `Reachable (${res.data.latency_ms ?? '?'} ms)`
          : res.data.message || unreachableMsg;
      } else {
        target.ok = false;
        target.msg = 'No response from server';
      }
    } catch (e) {
      target.ok = false;
      target.msg = `Request failed: ${e instanceof Error ? e.message : String(e)}`;
    } finally {
      target.testing = false;
    }
    setTimeout(() => {
      target.msg = '';
    }, 10000);
  }

  function testSyslog() {
    void runSinkTest(syslogTest, () => api.testSyslog(), 'Syslog receiver unreachable');
  }

  function testOtlpLogs() {
    void runSinkTest(otlpTest, () => api.testOtlpLogs(), 'OTLP collector unreachable');
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Log Export</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="section-hint">
        Stream access, WAF, and audit logs to an external syslog
        receiver (RFC 5424) and/or an OTLP logs collector. Sinks
        hot-reload on save - no proxy restart needed. Leave the syslog
        endpoint empty to disable the syslog sink.
      </p>

      <div class="settings-form-row">
        <label for="syslog-endpoint">Syslog endpoint</label>
        <input
          id="syslog-endpoint"
          type="text"
          bind:value={settingsForm.syslog_endpoint}
          placeholder="e.g. syslog.example.com:514 or [::1]:6514"
          autocomplete="off"
          onblur={checkEndpoint} oninput={checkEndpoint}
        />
        {#if endpointError}<span class="field-error" role="alert">{endpointError}</span>{/if}
        <span class="hint">
          <code>host:port</code> of the syslog receiver. Bracket IPv6
          literals (<code>[::1]:514</code>). Leave empty to disable
          the syslog sink.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="syslog-transport">Transport</label>
        <select id="syslog-transport" bind:value={settingsForm.syslog_transport}>
          <option value="udp">UDP (default)</option>
          <option value="tcp">TCP</option>
          <option value="tcp-tls">TCP + TLS</option>
        </select>
        {#if settingsForm.syslog_transport !== 'tcp-tls'}
          <span class="hint">
            Cleartext transport: exported records carry the audit
            trail, client IPs and WAF match excerpts, readable and
            forgeable by anyone on the path to the collector. Prefer
            TCP + TLS outside a trusted network.
          </span>
        {/if}
      </div>

      <div class="settings-form-row">
        <label for="syslog-facility">Facility</label>
        <input
          id="syslog-facility"
          type="number"
          bind:value={settingsForm.syslog_facility}
          min="0"
          max="23"
        />
        <span class="hint">
          RFC 5424 facility code (0-23). 16 = <code>local0</code>,
          the default.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="syslog-sev-access">Access log severity</label>
        <input
          id="syslog-sev-access"
          type="number"
          bind:value={settingsForm.syslog_severity_access}
          min="0"
          max="7"
        />
        <span class="hint">RFC 5424 severity (0-7). Default 6 = informational.</span>
      </div>

      <div class="settings-form-row">
        <label for="syslog-sev-waf">WAF event severity</label>
        <input
          id="syslog-sev-waf"
          type="number"
          bind:value={settingsForm.syslog_severity_waf}
          min="0"
          max="7"
        />
        <span class="hint">RFC 5424 severity (0-7). Default 4 = warning.</span>
      </div>

      <div class="settings-form-row">
        <label for="syslog-sev-audit">Audit log severity</label>
        <input
          id="syslog-sev-audit"
          type="number"
          bind:value={settingsForm.syslog_severity_audit}
          min="0"
          max="7"
        />
        <span class="hint">RFC 5424 severity (0-7). Default 5 = notice.</span>
      </div>

      <div class="settings-form-row">
        <label class="toggle-row">
          <input type="checkbox" bind:checked={settingsForm.syslog_access_enabled} />
          Export access logs
        </label>
      </div>

      <div class="settings-form-row">
        <label class="toggle-row">
          <input type="checkbox" bind:checked={settingsForm.syslog_waf_enabled} />
          Export WAF events
        </label>
      </div>

      <div class="settings-form-row">
        <label class="toggle-row">
          <input type="checkbox" bind:checked={settingsForm.syslog_audit_enabled} />
          Export audit logs
        </label>
      </div>

      {#if settingsForm.syslog_transport === 'tcp-tls'}
        <div class="settings-form-row">
          <label for="syslog-tls-ca">TLS CA bundle (PEM)</label>
          <textarea
            id="syslog-tls-ca"
            rows="4"
            bind:value={settingsForm.syslog_tls_ca_pem}
            placeholder="-----BEGIN CERTIFICATE-----"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
          <span class="hint">
            CA bundle used to verify the receiver. Leave empty to use
            the platform trust store.
          </span>
        </div>

        <div class="settings-form-row">
          <label for="syslog-tls-cert">TLS client certificate (PEM)</label>
          <textarea
            id="syslog-tls-cert"
            rows="4"
            bind:value={settingsForm.syslog_tls_client_cert_pem}
            placeholder="-----BEGIN CERTIFICATE-----"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
          <span class="hint">
            Optional client certificate chain for mTLS. Leave empty
            for server-only TLS.
          </span>
        </div>

        <div class="settings-form-row">
          <label for="syslog-tls-key">TLS client key (PEM)</label>
          <textarea
            id="syslog-tls-key"
            rows="4"
            bind:value={settingsForm.syslog_tls_client_key_pem}
            placeholder="-----BEGIN PRIVATE KEY-----"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
          <span class="hint">
            Secret: a saved key is shown as <code>**REDACTED**</code>
            and resending that sentinel leaves it unchanged. Clear the
            field to remove the key.
          </span>
        </div>
      {/if}

      <div class="settings-form-row">
        <label for="syslog-extra-sd">Extra structured data</label>
        <input
          id="syslog-extra-sd"
          type="text"
          bind:value={settingsForm.syslog_extra_sd}
          placeholder="e.g. env=prod,region=eu-west"
          autocomplete="off"
          onblur={checkExtraSd} oninput={checkExtraSd}
        />
        {#if extraSdError}<span class="field-error" role="alert">{extraSdError}</span>{/if}
        <span class="hint">
          Comma-separated <code>key=value</code> pairs added as RFC 5424
          structured data to every exported message. Leave empty for none.
        </span>
      </div>

      <h3 class="subsection-title">OTLP logs</h3>

      <div class="settings-form-row">
        <label class="toggle-row">
          <input type="checkbox" bind:checked={settingsForm.otlp_logs_enabled} />
          Export logs via OTLP
        </label>
        <span class="hint">
          Reuses the OTLP collector endpoint and protocol configured in
          the Observability section. Requires a Lorica binary built
          with the <code>otel</code> feature.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="otlp-logs-auth">OTLP logs authorization header</label>
        <input
          id="otlp-logs-auth"
          type="text"
          bind:value={settingsForm.otlp_logs_auth_header}
          placeholder="e.g. Bearer <token>"
          autocomplete="off"
        />
        <span class="hint">
          Sent as the <code>Authorization</code> header on OTLP log
          exports. Secret: a saved value is shown as
          <code>**REDACTED**</code> and resending that sentinel leaves
          it unchanged. Clear the field to remove the header.
        </span>
      </div>

      {#if $isSuperAdmin}
        <div class="settings-form-row test-connection-row">
          <div class="test-connection-inner">
            <button
              type="button"
              class="btn btn-secondary"
              onclick={testSyslog}
              disabled={syslogTest.testing}
            >
              {syslogTest.testing ? 'Testing...' : 'Test syslog'}
            </button>
            {#if syslogTest.msg}
              <span class="test-msg {syslogTest.ok ? 'test-ok' : 'test-err'}" role="status">
                {syslogTest.msg}
              </span>
            {/if}
            <button
              type="button"
              class="btn btn-secondary"
              onclick={testOtlpLogs}
              disabled={otlpTest.testing}
            >
              {otlpTest.testing ? 'Testing...' : 'Test OTLP logs'}
            </button>
            {#if otlpTest.msg}
              <span class="test-msg {otlpTest.ok ? 'test-ok' : 'test-err'}" role="status">
                {otlpTest.msg}
              </span>
            {/if}
          </div>
          <span class="hint">
            Probes the CURRENTLY SAVED sink settings (not the form
            values above). Save first if you changed anything.
          </span>
        </div>
      {/if}

      {#if settingsError}
        <div class="settings-form-error">{settingsError}</div>
      {/if}
      {#if $isSuperAdmin}
        <div class="settings-dialog-actions">
          <button class="btn btn-primary" onclick={onSave} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Log Export Settings'}
          </button>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .section-hint {
    color: var(--color-text-muted, #666);
    font-size: 0.9em;
    margin: 0 0 1rem;
  }
  .subsection-title {
    font-size: 0.9375rem;
    margin: 1.25rem 0 0.5rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--color-border);
  }
  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }
  .toggle-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }
  .test-connection-row {
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
    margin-top: var(--space-4);
  }
  .test-connection-inner {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.25rem;
  }
  .test-msg {
    font-size: 0.8125rem;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }
  .test-ok {
    color: var(--color-green, #1a7f37);
    background: var(--color-green-subtle, rgba(26, 127, 55, 0.1));
  }
  .test-err {
    color: var(--color-danger, #b32);
    background: var(--color-danger-subtle, rgba(187, 51, 51, 0.1));
  }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
</style>
