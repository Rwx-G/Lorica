<script lang="ts">
  import type { CertificateResponse, RouteResponse } from '../../lib/api';
  import CertExpiryBadge from '../CertExpiryBadge.svelte';

  interface Props {
    certificates: CertificateResponse[];
    routes: RouteResponse[];
    warningDays: number;
    criticalDays: number;
    renewingId: string;
    onView: (cert: CertificateResponse) => void;
    onEdit: (cert: CertificateResponse) => void;
    onRenew: (cert: CertificateResponse) => void;
    onDelete: (cert: CertificateResponse) => void;
  }

  let {
    certificates,
    routes,
    warningDays,
    criticalDays,
    renewingId,
    onView,
    onEdit,
    onRenew,
    onDelete,
  }: Props = $props();

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function getRoutesForCert(certId: string): RouteResponse[] {
    return routes.filter((r) => r.certificate_id === certId);
  }

  const eyeIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
  const renewIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
</script>

<div class="table-wrapper">
  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>Issuer</th>
        <th>Expires</th>
        <th>Days Left</th>
        <th>Status</th>
        <th>Routes</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each certificates as cert (cert.id)}
        <tr>
          <td class="domain">
            <button class="link-btn" onclick={() => onView(cert)}>{cert.domain}</button>
            {#if cert.san_domains.length > 0}
              <span class="san-count" title={cert.san_domains.join(', ')}>+{cert.san_domains.length} SAN</span>
            {/if}
            {#if cert.is_acme}
              <span class="cert-source-badge acme" title={cert.acme_method || 'http01'}>ACME{#if cert.acme_method && cert.acme_method !== 'http01'} ({cert.acme_method.replace('dns01-', '')}){/if}{#if cert.acme_auto_renew} &#x21bb;{/if}</span>
            {:else}
              <span class="cert-source-badge manual">Manual</span>
            {/if}
          </td>
          <td class="issuer">{cert.issuer}</td>
          <td>{formatDate(cert.not_after)}</td>
          <td>
            {#if true}
              {@const daysLeft = Math.floor((new Date(cert.not_after).getTime() - Date.now()) / (1000 * 60 * 60 * 24))}
              <span class="days-left" style="color: {daysLeft < 7 ? 'var(--color-red)' : daysLeft <= 30 ? 'var(--color-orange, #fb923c)' : 'var(--color-green)'}; font-weight: 700; font-size: 1rem;">
                {daysLeft}d
              </span>
            {/if}
          </td>
          <td><CertExpiryBadge notAfter={cert.not_after} {warningDays} {criticalDays} /></td>
          <td>
            {#if getRoutesForCert(cert.id).length === 0}
              <span class="text-muted">None</span>
            {:else}
              <span class="route-count">{getRoutesForCert(cert.id).length} route{getRoutesForCert(cert.id).length > 1 ? 's' : ''}</span>
            {/if}
          </td>
          <td class="actions">
            <button class="btn-icon" title="View details" aria-label="View details" onclick={() => onView(cert)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html eyeIcon}
            </button>
            <button class="btn-icon" title="Edit" aria-label="Edit" onclick={() => onEdit(cert)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html editIcon}
            </button>
            {#if cert.is_acme}
              <button class="btn-icon" title="Renew" aria-label="Renew certificate" onclick={() => onRenew(cert)} disabled={renewingId === cert.id}>
                <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                {@html renewIcon}
              </button>
            {/if}
            <button class="btn-icon btn-icon-danger" title="Delete" aria-label="Delete" onclick={() => onDelete(cert)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html trashIcon}
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .domain {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .link-btn {
    background: none;
    border: none;
    color: var(--color-primary);
    font-weight: 600;
    font-size: 0.875rem;
    padding: 0;
    text-decoration: none;
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .cert-source-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    margin-left: 0.375rem;
    vertical-align: middle;
  }

  .cert-source-badge.acme {
    background: rgba(34, 197, 94, 0.15);
    color: var(--color-green);
  }

  .cert-source-badge.manual {
    background: rgba(148, 163, 184, 0.15);
    color: var(--color-text-muted);
  }

  .san-count {
    margin-left: 0.5rem;
    font-size: 0.7rem;
    font-weight: 400;
    color: var(--color-text-muted);
    background: rgba(148, 163, 184, 0.1);
    padding: 0.1rem 0.4rem;
    border-radius: 9999px;
  }

  .issuer {
    color: var(--color-text-muted);
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .route-count {
    color: var(--color-text);
  }
</style>
