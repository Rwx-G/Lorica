<script lang="ts">
  import { api } from '../../lib/api';

  interface ObservabilityFormShape {
    otlp_endpoint: string;
    otlp_protocol: string;
    otlp_service_name: string;
    otlp_sampling_ratio: number;
    geoip_db_path: string;
    geoip_auto_update_enabled: boolean;
    asn_db_path: string;
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
    const res = await api.testOtel();
    if (res.error) {
      testOk = false;
      testMsg = res.error.message;
    } else if (res.data) {
      testOk = res.data.ok;
      testMsg = res.data.ok
        ? `OK (${res.data.latency_ms ?? '?'} ms)`
        : res.data.message;
    }
    testing = false;
    setTimeout(() => {
      testMsg = '';
    }, 8000);
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
        OpenTelemetry tracing (OTLP), GeoIP database, and ASN database. The
        OTel exporter, GeoIP resolver and ASN resolver hot-reload on save —
        no proxy restart needed. Leave an endpoint / path empty to disable
        the feature.
      </p>

      <h3>OpenTelemetry</h3>

      <div class="settings-form-row">
        <div class="settings-form-group">
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
        <div class="settings-form-group">
          <label for="otlp-protocol">Protocol</label>
          <select id="otlp-protocol" bind:value={settingsForm.otlp_protocol}>
            <option value="http-proto">HTTP + protobuf (default)</option>
            <option value="http-json">HTTP + JSON</option>
            <option value="grpc">gRPC</option>
          </select>
        </div>
      </div>

      <div class="settings-form-row">
        <div class="settings-form-group">
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
        <div class="settings-form-group">
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
            Fraction of requests exported. 0.1 ≈ Grafana / Tempo default,
            1.0 = every request (development). Uses ParentBased so a sampled
            upstream trace always carries through.
          </span>
        </div>
      </div>

      <div class="settings-form-row">
        <button
          type="button"
          class="btn-secondary"
          onclick={testConnection}
          disabled={testing || !settingsForm.otlp_endpoint.trim()}
        >
          {testing ? 'Testing...' : 'Test connection'}
        </button>
        {#if testMsg}
          <span class={testOk ? 'test-ok' : 'test-err'}>{testMsg}</span>
        {/if}
      </div>
      <p class="hint small">
        Test mints one canary span using the CURRENTLY SAVED settings (not
        the form values above). Save first if you edited the endpoint.
      </p>

      <h3>GeoIP</h3>

      <div class="settings-form-row">
        <div class="settings-form-group">
          <label for="geoip-db-path">GeoIP database path</label>
          <input
            id="geoip-db-path"
            type="text"
            bind:value={settingsForm.geoip_db_path}
            placeholder="/var/lib/lorica/dbip-country-lite.mmdb"
            autocomplete="off"
          />
          <span class="hint">
            Absolute path to a <code>.mmdb</code> country database. Default
            source is DB-IP Lite Country (CC-BY 4.0, monthly refresh, no
            account). Hot-reloaded on save.
          </span>
        </div>
        <div class="settings-form-group">
          <label>
            <input
              type="checkbox"
              bind:checked={settingsForm.geoip_auto_update_enabled}
            />
            Auto-update weekly
          </label>
          <span class="hint">
            Downloads the current month's DB-IP Lite every 24 h, validates
            via a sanity probe, and atomic-renames onto <code>geoip_db_path</code>.
            Opt in after reading the CC-BY 4.0 attribution note in
            <code>NOTICE</code>.
          </span>
        </div>
      </div>

      <h3>ASN</h3>

      <div class="settings-form-row">
        <div class="settings-form-group">
          <label for="asn-db-path">ASN database path</label>
          <input
            id="asn-db-path"
            type="text"
            bind:value={settingsForm.asn_db_path}
            placeholder="/var/lib/lorica/dbip-asn-lite.mmdb"
            autocomplete="off"
          />
          <span class="hint">
            Absolute path to a <code>.mmdb</code> ASN database. DB-IP ASN Lite
            (CC-BY 4.0) is the free default source. Required for the
            <code>bypass.asns</code> category on the bot-protection filter;
            an unset path makes that bypass a silent no-op.
          </span>
        </div>
      </div>

      <div class="settings-form-row">
        <button
          type="button"
          class="btn-primary"
          onclick={onSave}
          disabled={settingsSaving}
        >
          {settingsSaving ? 'Saving...' : 'Save observability settings'}
        </button>
        {#if settingsMsg}<span class="ok">{settingsMsg}</span>{/if}
        {#if settingsError}<span class="err">{settingsError}</span>{/if}
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
  .hint.small {
    font-size: 0.8em;
    margin-top: 0.25rem;
  }
  .test-ok {
    color: var(--color-success, #1a7f37);
    font-size: 0.9em;
    margin-left: 0.75rem;
  }
  .test-err {
    color: var(--color-danger, #b32);
    font-size: 0.9em;
    margin-left: 0.75rem;
  }
  .ok {
    color: var(--color-success, #1a7f37);
    font-size: 0.9em;
    margin-left: 0.75rem;
  }
  .err {
    color: var(--color-danger, #b32);
    font-size: 0.9em;
    margin-left: 0.75rem;
  }
  h3 {
    margin-top: 1.5rem;
    font-size: 1em;
    font-weight: 600;
  }
</style>
