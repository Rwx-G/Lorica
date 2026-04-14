<script lang="ts">
  import type { CertificateDetailResponse, RouteResponse } from '../../lib/api';
  import CertExpiryBadge from '../CertExpiryBadge.svelte';

  interface Props {
    detailCert: CertificateDetailResponse | null;
    detailLoading: boolean;
    routes: RouteResponse[];
    warningDays: number;
    criticalDays: number;
    onClose: () => void;
  }

  let { detailCert, detailLoading, routes, warningDays, criticalDays, onClose }: Props = $props();

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function getRouteHostname(routeId: string): string {
    const r = routes.find((r) => r.id === routeId);
    return r ? `${r.hostname}${r.path_prefix}` : routeId.slice(0, 8);
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onClose();
  }
</script>

<div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) onClose(); }} onkeydown={handleKeydown} role="dialog" aria-modal="true" tabindex="-1">
  <div class="modal modal-wide" role="document">
    {#if detailLoading}
      <p class="loading">Loading certificate details...</p>
    {:else if detailCert}
      <h2>Certificate: {detailCert.domain}</h2>

      <div class="detail-grid">
        <div class="detail-row">
          <span class="detail-label">Domain</span>
          <span class="detail-value">{detailCert.domain}</span>
        </div>
        {#if detailCert.san_domains.length > 0}
          <div class="detail-row">
            <span class="detail-label">SAN Domains</span>
            <span class="detail-value">{detailCert.san_domains.join(', ')}</span>
          </div>
        {/if}
        <div class="detail-row">
          <span class="detail-label">Issuer</span>
          <span class="detail-value">{detailCert.issuer}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Valid From</span>
          <span class="detail-value">{formatDate(detailCert.not_before)}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Valid Until</span>
          <span class="detail-value">
            {formatDate(detailCert.not_after)}
            <CertExpiryBadge notAfter={detailCert.not_after} {warningDays} {criticalDays} />
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Fingerprint (SHA-256)</span>
          <span class="detail-value mono">{detailCert.fingerprint}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">ACME</span>
          <span class="detail-value">{detailCert.is_acme ? 'Yes' : 'No'}{detailCert.acme_auto_renew ? ' (auto-renew)' : ''}</span>
        </div>
        {#if detailCert.acme_method}
          <div class="detail-row">
            <span class="detail-label">ACME Method</span>
            <span class="detail-value">
              {detailCert.acme_method}
              {#if detailCert.acme_method.startsWith('dns01-') && detailCert.acme_method !== 'dns01-manual'}
                <span style="display:inline-block;padding:0.0625rem 0.375rem;border-radius:9999px;font-size:0.625rem;font-weight:600;text-transform:uppercase;margin-left:0.375rem;background:rgba(34,197,94,0.15);color:var(--color-green);">credentials stored</span>
              {/if}
            </span>
          </div>
        {/if}
        <div class="detail-row">
          <span class="detail-label">Created</span>
          <span class="detail-value">{formatDate(detailCert.created_at)}</span>
        </div>
      </div>

      <div class="detail-section">
        <h3>Associated Routes</h3>
        {#if detailCert.associated_routes.length === 0}
          <p class="text-muted">No routes are using this certificate.</p>
        {:else}
          <ul class="route-list">
            {#each detailCert.associated_routes as routeId (routeId)}
              <li>{getRouteHostname(routeId)}</li>
            {/each}
          </ul>
        {/if}
      </div>

      <div class="detail-section">
        <h3>Certificate Chain (PEM)</h3>
        <pre class="pem-block">{detailCert.cert_pem}</pre>
      </div>

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={onClose}>Close</button>
      </div>
    {/if}
  </div>
</div>

<style>
  .modal-wide {
    max-width: 680px;
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.75rem;
    word-break: break-all;
  }

  .detail-grid {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
  }

  .detail-row {
    display: flex;
    gap: 1rem;
    align-items: baseline;
    font-size: 0.875rem;
  }

  .detail-label {
    flex: 0 0 160px;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    font-weight: 500;
  }

  .detail-value {
    color: var(--color-text);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .detail-section {
    margin-bottom: 1.25rem;
  }

  .detail-section h3 {
    margin-bottom: 0.5rem;
  }

  .route-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .route-list li {
    padding: 0.375rem 0;
    font-size: 0.875rem;
    color: var(--color-text);
    border-bottom: 1px solid var(--color-border);
  }

  .route-list li:last-child {
    border-bottom: none;
  }

  .pem-block {
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    padding: 0.75rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    color: var(--color-text-muted);
    margin: 0;
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.5rem;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }
</style>
