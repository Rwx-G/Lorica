<script lang="ts">
  import type { LoricaRouteImport } from '../../lib/nginx-parser';
  import { CHECK_ICON, X_ICON } from './maps';
  import type { ApplyResult, BackendCheck, CertEntry } from './types';

  interface Props {
    applyResults: ApplyResult[];
    certEntries: CertEntry[];
    importRoutes: LoricaRouteImport[];
    backendChecks: BackendCheck[];
    tlsSkipVerifyAddressesPreview: Set<string>;
    onFinish: () => void;
  }

  let {
    applyResults,
    certEntries,
    importRoutes,
    backendChecks,
    tlsSkipVerifyAddressesPreview,
    onFinish,
  }: Props = $props();
</script>

<div class="step-content">
  <h3>Import results</h3>
  <div class="results-list">
    {#each applyResults as result, i (i)}
      <div class="result-row" class:success={result.success} class:failure={!result.success}>
        <span class="result-icon">
          {#if result.success}
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            {@html CHECK_ICON}
          {:else}
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            {@html X_ICON}
          {/if}
        </span>
        <span class="result-type">{result.type === 'backend' ? 'Backend' : 'Route'}</span>
        <span class="result-label">{result.label}</span>
        {#if result.error}
          <span class="result-error">{result.error}</span>
        {/if}
      </div>
    {/each}
  </div>

  {#if certEntries.some((c) => c.mode === 'skip')}
    <div class="cert-notice">
      <strong>TLS certificates skipped</strong>
      <p>Some certificates were skipped during import. Configure them in the Certificates page (upload or ACME), then assign them to the routes in the Route Drawer to enable HTTPS.</p>
    </div>
  {/if}

  {#if importRoutes.some((r) => r._backendTlsSkipVerify)}
    <div class="cert-notice">
      <strong>Backend TLS skip verify configured</strong>
      <p>Some backends use HTTPS upstream (proxy_pass https://). The <code>tls_skip_verify</code> flag has been {backendChecks.some(c => c.exists && tlsSkipVerifyAddressesPreview.has(c.address)) ? 'enabled on existing backends and ' : ''}set on newly created backends. Verify this setting in the Backends page if needed.</p>
    </div>
  {/if}

  <div class="step-actions">
    <button class="btn btn-primary" onclick={onFinish}>Close</button>
  </div>
</div>
