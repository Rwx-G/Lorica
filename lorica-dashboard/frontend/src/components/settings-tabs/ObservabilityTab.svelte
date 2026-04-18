<script lang="ts">
  import { api } from '../../lib/api';

  interface ObservabilityFormShape {
    otlp_endpoint: string;
    otlp_protocol: string;
    otlp_service_name: string;
    otlp_sampling_ratio: number;
  }

  interface Props {
    settingsForm: ObservabilityFormShape;
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

  // --- Test connection state ---
  let testing = $state(false);
  let testMsg = $state('');
  let testOk = $state(false);

  async function testConnection() {
    testing = true;
    testMsg = '';
    testOk = false;
    try {
      const res = await api.testOtel();
      if (res.error) {
        testOk = false;
        testMsg = res.error.message || 'Test connection failed (unknown error)';
      } else if (res.data) {
        testOk = res.data.ok;
        if (res.data.ok) {
          const latency = res.data.latency_ms ?? '?';
          testMsg = `Reachable (${latency} ms)`;
        } else {
          testMsg = res.data.message || 'Collector unreachable';
        }
      } else {
        testOk = false;
        testMsg = 'No response from server';
      }
    } catch (e) {
      testOk = false;
      testMsg = `Request failed: ${e instanceof Error ? e.message : String(e)}`;
    } finally {
      testing = false;
    }
    setTimeout(() => {
      testMsg = '';
    }, 10000);
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Observability</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="section-hint">
        OpenTelemetry distributed tracing via OTLP (HTTP/protobuf, HTTP/JSON,
        or gRPC). The exporter hot-reloads on save - no proxy restart needed.
        Leave the endpoint empty to disable tracing.
      </p>

      <div class="settings-form-row">
        <label for="otlp-endpoint">OTLP endpoint</label>
        <input
          id="otlp-endpoint"
          type="text"
          bind:value={settingsForm.otlp_endpoint}
          placeholder="e.g. http://jaeger:4318 or https://tempo.example.com:4317"
          autocomplete="off"
        />
        <span class="hint">
          Full base URL. For <code>http-proto</code> / <code>http-json</code>
          Lorica appends <code>/v1/traces</code> automatically if missing.
          Leave empty to disable OTel export.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="otlp-protocol">Protocol</label>
        <select id="otlp-protocol" bind:value={settingsForm.otlp_protocol}>
          <option value="http-proto">HTTP + protobuf (default)</option>
          <option value="http-json">HTTP + JSON</option>
          <option value="grpc">gRPC</option>
        </select>
      </div>

      <div class="settings-form-row">
        <label for="otlp-service-name">Service name</label>
        <input
          id="otlp-service-name"
          type="text"
          bind:value={settingsForm.otlp_service_name}
          placeholder="lorica"
          autocomplete="off"
        />
        <span class="hint">
          Exposed as <code>service.name</code> on every exported span.
          Defaults to <code>lorica</code>.
        </span>
      </div>

      <div class="settings-form-row">
        <label for="otlp-sampling">
          Sampling ratio
          <strong>{(settingsForm.otlp_sampling_ratio ?? 0).toFixed(2)}</strong>
        </label>
        <input
          id="otlp-sampling"
          type="range"
          min="0"
          max="1"
          step="0.05"
          bind:value={settingsForm.otlp_sampling_ratio}
        />
        <span class="hint">
          Fraction of requests exported. 0.1 is the Grafana / Tempo default,
          1.0 = every request (development). Uses ParentBased so a sampled
          upstream trace always carries through.
        </span>
      </div>

      <div class="settings-form-row test-connection-row">
        <div class="test-connection-inner">
          <button
            type="button"
            class="btn btn-secondary"
            onclick={testConnection}
            disabled={testing}
          >
            {testing ? 'Testing...' : 'Test connection'}
          </button>
          {#if testMsg}
            <span class="test-msg {testOk ? 'test-ok' : 'test-err'}" role="status">
              {testMsg}
            </span>
          {/if}
        </div>
        <span class="hint">
          Probes the CURRENTLY SAVED endpoint (not the form values above).
          Save first if you changed the endpoint. A 4xx response from the
          collector still counts as reachable - only connection refused, DNS
          failure, or timeout mean unreachable.
        </span>
      </div>

      {#if settingsError}
        <div class="settings-form-error">{settingsError}</div>
      {/if}
      <div class="settings-dialog-actions">
        <button class="btn btn-primary" onclick={onSave} disabled={settingsSaving}>
          {settingsSaving ? 'Saving...' : 'Save Observability Settings'}
        </button>
      </div>
    </div>
  {/if}
</section>

<style>
  .section-hint {
    color: var(--color-text-muted, #666);
    font-size: 0.9em;
    margin: 0 0 1rem;
  }
  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }
  .form-success {
    color: var(--color-green);
    font-size: 0.8125rem;
    margin: 0.5rem 0;
  }
  .test-connection-row {
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
    margin-top: var(--space-4);
  }
  .test-connection-inner {
    display: flex;
    align-items: center;
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
</style>
